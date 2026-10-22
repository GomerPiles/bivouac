//go:build windows

package guestagent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	guestDirectory          = `C:\ProgramData\Bivouac\Guest`
	agentLogDirectory       = `C:\ProgramData\Bivouac\Agent`
	maxReceiveSize    int64 = 1 << 30 // Existing Windows delivery bound.
)

type guestDir struct {
	path    string
	handles []windows.Handle // Pin every ancestor against rename/replacement.
	sd      *windows.SECURITY_DESCRIPTOR
}

func (d *guestDir) Close() {
	for i := len(d.handles) - 1; i >= 0; i-- {
		_ = windows.CloseHandle(d.handles[i])
	}
}

func openGuestDirectory(path string) (_ *guestDir, err error) {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) || strings.Contains(path[2:], ":") {
		return nil, errors.New("invalid guest directory")
	}
	path = filepath.Clean(path)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	d := &guestDir{path: path, sd: sd}
	defer func() {
		if err != nil {
			d.Close()
		}
	}()
	volume := filepath.VolumeName(path) + `\`
	parts := strings.Split(strings.TrimPrefix(path, volume), `\`)
	current := volume
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			current = filepath.Join(current, parts[i])
		}
		protected := current == path || ((path == guestDirectory || path == agentLogDirectory) && current == filepath.Dir(path))
		text, e := windows.UTF16PtrFromString(current)
		if e != nil {
			return nil, e
		}
		if protected {
			sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
			e = windows.CreateDirectory(text, &sa)
			if e != nil && !errors.Is(e, windows.ERROR_ALREADY_EXISTS) {
				return nil, fmt.Errorf("directory create %d: %w", i, e)
			}
		}
		access := uint32(windows.FILE_READ_ATTRIBUTES)
		if protected {
			access |= windows.READ_CONTROL
		}
		h, e := windows.CreateFile(text, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if e != nil {
			return nil, fmt.Errorf("directory open %d: %w", i, e)
		}
		d.handles = append(d.handles, h)
		var info windows.ByHandleFileInformation
		if e = windows.GetFileInformationByHandle(h, &info); e != nil {
			return nil, e
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return nil, errors.New("guest directory is not ordinary")
		}
		if protected {
			if e := checkGuestACL(h, user.User.Sid); e != nil {
				return nil, e
			}
		}
	}
	return d, nil
}

func checkGuestACL(h windows.Handle, user *windows.SID) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	trusted := func(sid *windows.SID) bool {
		return sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return errors.New("untrusted guest directory owner")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("guest directory ACL is not protected")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("guest directory ACL unavailable")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported guest directory ACL")
		}
		// #nosec G103 -- GetAce validates the variable-sized SID in this ACE.
		if !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return errors.New("guest directory grants another account access")
		}
	}
	return nil
}

// open creates/opens only fixed or random basenames, never follows a reparse
// point and rejects hard links. Ancestor handles prevent path substitution.
func (d *guestDir) open(name string, access, disposition, share uint32) (*os.File, error) {
	return d.openFlags(name, access, disposition, share, 0)
}

func (d *guestDir) openFlags(name string, access, disposition, share, flags uint32) (*os.File, error) {
	if name == "" || strings.ContainsAny(name, `\/:`) || filepath.Base(name) != name {
		return nil, errors.New("invalid guest filename")
	}
	text, err := windows.UTF16PtrFromString(filepath.Join(d.path, name))
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: d.sd}
	h, err := windows.CreateFile(text, access|windows.FILE_READ_ATTRIBUTES, share, &sa, disposition, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|flags, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		_ = windows.CloseHandle(h)
		return nil, errors.New("guest file is not ordinary")
	}
	return os.NewFile(uintptr(h), name), nil
}

func (d *guestDir) absentOrRegular(name string) (bool, error) {
	f, err := d.open(name, windows.GENERIC_READ, windows.OPEN_EXISTING, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, f.Close()
}

// lock serializes receivers. The phase-3 adapter must also hold this exclusive
// .receive.lock handle while writing `launched`, so launch and publish cannot
// race. The fixed directory is shared with that adapter, not configurable by
// a host command. Contention fails closed and does not replay a mutation.
func (d *guestDir) lock() (*os.File, error) {
	return d.open(".receive.lock", windows.GENERIC_READ|windows.GENERIC_WRITE, windows.OPEN_ALWAYS, 0)
}

func receiveGuest(ctx context.Context, name string, size int64, digest string, input io.Reader) error {
	return receive(ctx, guestDirectory, name, size, digest, input)
}

func receive(ctx context.Context, directory, name string, size int64, digest string, input io.Reader) error {
	switch name {
	case "bivouac-helper.exe", "bivouac-config.json", "bivouac-runner.zip":
	default:
		return errors.New("receiver name refused")
	}
	expected, err := hex.DecodeString(digest)
	if size < 0 || size > maxReceiveSize || err != nil || len(expected) != sha256.Size {
		return errors.New("invalid receiver metadata")
	}
	if err := ctx.Err(); err != nil {
		return errors.New("receiver canceled")
	}
	d, err := openGuestDirectory(directory)
	if err != nil {
		return errors.New("receiver directory refused")
	}
	defer d.Close()
	lock, err := d.lock()
	if err != nil {
		return errors.New("receiver busy")
	}
	defer func() { _ = lock.Close() }()
	check := func() error {
		absent, err := d.absentOrRegular("launched")
		if err != nil || !absent {
			return errors.New("receiver launch marker present")
		}
		_, err = d.absentOrRegular(name)
		return err
	}
	if err := check(); err != nil {
		return errors.New("receiver destination refused")
	}
	temp := ".receive-" + rand.Text() + ".tmp"
	// Delete-on-close also cleans up if connection cancellation kills this
	// receiver process before Go defers can run. The handle is never inherited.
	f, err := d.openFlags(temp, windows.GENERIC_WRITE|windows.DELETE, windows.CREATE_NEW, windows.FILE_SHARE_DELETE, windows.FILE_FLAG_DELETE_ON_CLOSE)
	if err != nil {
		return errors.New("receiver temporary file unavailable")
	}
	defer func() { _ = f.Close(); _ = os.Remove(filepath.Join(directory, temp)) }()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(input, size+1))
	if err != nil || n != size || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), digest) {
		return errors.New("receiver integrity failed")
	}
	if err := f.Sync(); err != nil {
		return errors.New("receiver flush failed")
	}
	if err := ctx.Err(); err != nil {
		return errors.New("receiver canceled")
	}
	if err := check(); err != nil {
		return errors.New("receiver destination refused")
	}
	if err := d.publish(f, name); err != nil {
		return errors.New("receiver publish failed")
	}
	return nil
}

func (d *guestDir) publish(f *os.File, name string) error {
	// Rename the verified file by its still-open handle. No source-name lookup
	// or close/reopen window can substitute a different file. The protected
	// parent remains pinned. The delete-on-close state stays set until the
	// atomic rename succeeds, then is cleared on this same handle.
	text, err := windows.UTF16FromString(filepath.Join(d.path, name))
	if err != nil {
		return err
	}
	type renameInfo struct {
		flags  uint32
		root   windows.Handle
		length uint32
		name   [1]uint16
	}
	var layout renameInfo
	offset := unsafe.Offsetof(layout.name)
	buf := make([]byte, int(offset)+len(text)*2)
	// #nosec G103 -- Native structure layout plus a bounded fixed allowlist name.
	info := (*renameInfo)(unsafe.Pointer(&buf[0]))
	info.flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	info.length = uint32((len(text) - 1) * 2) // #nosec G115 -- Windows paths are bounded to 32767 UTF-16 units.
	// #nosec G103 -- Buffer reserves the entire UTF-16 name and trailing NUL.
	copy(unsafe.Slice(&info.name[0], len(text)), text)
	if err := windows.SetFileInformationByHandle(windows.Handle(f.Fd()), windows.FileRenameInfoEx, &buf[0], uint32(len(buf))); err != nil {
		return err
	} // #nosec G115 -- Fixed small allowlist name.
	flags := uint32(windows.FILE_DISPOSITION_ON_CLOSE | windows.FILE_DISPOSITION_DO_NOT_DELETE)
	// #nosec G103 -- One fixed DWORD clears this handle's delete-on-close state.
	return windows.SetFileInformationByHandle(windows.Handle(f.Fd()), windows.FileDispositionInfoEx, (*byte)(unsafe.Pointer(&flags)), 4)
}
