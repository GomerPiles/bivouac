//go:build windows

// Package winhost holds Windows host checks shared by Windows-hosted providers:
// administrator-protected storage, private staging directories and system
// OpenSSH resolution. It contacts no VM engine.
package winhost

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// trustedInstaller is the servicing stack's service SID. It owns system
// locations such as volume roots and Program Files, and only that service
// runs with it, so it is as trusted as SYSTEM here.
const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

func administrative(sid *windows.SID) bool {
	return sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.String() == trustedInstaller
}

// CheckProtected requires an administrator-only file or directory whose
// ancestors cannot rename, replace or re-permission it. Privileged code uses
// it to refuse input that the normal-user side it limits could edit.
func CheckProtected(path string) error {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return errors.New("protected path must be local and absolute")
	}
	path = filepath.Clean(path)
	if err := checkProtected(path, false); err != nil {
		return err
	}
	return CheckProtectedParents(path)
}

// CheckProtectedParents checks only the ancestors of path, before privileged
// code creates path itself.
func CheckProtectedParents(path string) error {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return errors.New("protected path must be local and absolute")
	}
	path = filepath.Clean(path)
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		if err := checkProtected(current, true); err != nil {
			return err
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}

func checkProtected(path string, parent bool) error {
	text, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(text)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("protected path is a reparse point")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if !administrative(owner) {
		return errors.New("protected storage owner must be Administrators, SYSTEM or TrustedInstaller")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("protected storage requires an explicit access policy")
	}
	const fileDeleteChild = 0x0040
	write := uint32(windows.GENERIC_ALL | windows.WRITE_DAC | windows.WRITE_OWNER | fileDeleteChild)
	// Creating an unrelated child in a parent cannot replace a protected
	// entry. DELETE on a non-volume ancestor can rename the entire chain;
	// a volume root itself is not a renameable filesystem entry.
	if filepath.Clean(path) != filepath.VolumeName(path)+string(filepath.Separator) {
		write |= windows.DELETE
	}
	if !parent {
		write |= windows.GENERIC_WRITE | windows.DELETE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&0x08 != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported protected storage access entry")
		}
		if uint32(ace.Mask)&write == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- GetAce returns a validated ACCESS_ALLOWED_ACE whose trailing field is the variable-length SID.
		if !administrative(sid) {
			return errors.New("protected storage grants non-administrator mutation rights")
		}
	}
	return nil
}

// PrivateDirectory creates a normal-user staging directory with explicit
// Windows ACLs before any JIT bytes are written. Windows ignores Unix mode bits.
func PrivateDirectory(base string) (string, error) {
	dir, err := os.MkdirTemp(base, "bivouac-transfer-")
	if err != nil {
		return "", err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		_ = os.Remove(dir)
		return "", err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		_ = os.Remove(dir)
		return "", err
	}
	acl, _, err := sd.DACL()
	if err == nil {
		err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	}
	if err != nil {
		_ = os.Remove(dir)
		return "", err
	}
	return dir, nil
}

// OpenSSH resolves system OpenSSH instead of an ambient PATH.
func OpenSSH() (ssh, scp string, err error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return "", "", err
	}
	return filepath.Join(system, "OpenSSH", "ssh.exe"), filepath.Join(system, "OpenSSH", "scp.exe"), nil
}
