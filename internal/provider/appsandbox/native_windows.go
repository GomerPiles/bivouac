//go:build windows

package appsandbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/control"
	"golang.org/x/sys/windows"
)

func hideCommandWindow(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }

// trustedInstaller is the servicing stack's service SID. It owns system
// locations such as volume roots and Program Files, and only that service
// runs with it, so it is as trusted as SYSTEM here.
const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

func administrative(sid *windows.SID) bool {
	return sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.String() == trustedInstaller
}

// checkProtectedChain requires an administrator-only file or directory whose
// ancestors cannot rename, replace or re-permission it.
func checkProtectedChain(path string) error {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return errors.New("protected path must be local and absolute")
	}
	path = filepath.Clean(path)
	if err := checkProtected(path, false); err != nil {
		return err
	}
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		if err := checkProtected(current, true); err != nil {
			return err
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}

// CheckProtectedFile lets the broker command refuse configuration that the
// normal-user side it limits could edit, before trusting any of its values.
func CheckProtectedFile(path string) error { return checkProtectedChain(path) }

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
		return errors.New("protected broker path is a reparse point")
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
		return errors.New("broker storage owner must be Administrators, SYSTEM or TrustedInstaller")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("broker storage requires an explicit access policy")
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
			return errors.New("unsupported broker storage access entry")
		}
		if uint32(ace.Mask)&write == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- GetAce returns a validated ACCESS_ALLOWED_ACE whose trailing field is the variable-length SID.
		if !administrative(sid) {
			return errors.New("broker storage grants non-administrator mutation rights")
		}
	}
	return nil
}
func protectNewRoot(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) == filepath.VolumeName(path)+string(filepath.Separator) || strings.HasPrefix(path, `\\`) {
		return errors.New("broker root must be a dedicated local absolute directory")
	}
	parent := filepath.Dir(filepath.Clean(path))
	for current := parent; ; current = filepath.Dir(current) {
		if err := checkProtected(current, true); err != nil {
			return err
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil); err != nil {
		return err
	}
	return checkProtected(path, false)
}

// OpenNativeEngine never elevates, launches a daemon, registers a runner, or
// modifies global switches. It must be invoked by an operator-started elevated
// broker in an already available App Sandbox launch context.
func OpenNativeEngine(ctx context.Context, opts BrokerOptions) (*Engine, func(), error) {
	if opts.MaxInstances == 0 {
		opts.MaxInstances = 1
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, nil, errors.New("appsandbox lifecycle broker requires operator-approved administrator startup")
	}
	if !identifier(opts.ControllerID, 64) || !identifier(opts.Baseline, 15) || !identifier(opts.GuestUser, 32) || opts.MaxCPU < 1 || opts.MaxCPU > 1024 || opts.MaxMemoryMB < 512 || opts.MaxMemoryMB > 1048576 || opts.MaxDiskGB < 16 || opts.MaxDiskGB > 2048 || opts.MaxInstances < 1 || opts.MaxInstances > 16 {
		return nil, nil, errors.New("invalid privileged broker resource bounds")
	}
	if !filepath.IsAbs(opts.Root) || filepath.Clean(opts.Root) == filepath.VolumeName(opts.Root)+string(filepath.Separator) || strings.HasPrefix(opts.Root, `\\`) ||
		!filepath.IsAbs(opts.BaselineDisk) || strings.HasPrefix(opts.BaselineDisk, `\\`) || !filepath.IsAbs(opts.Discovery) || len(opts.BaselineSHA256) != 64 {
		return nil, nil, errors.New("broker requires pinned template and native discovery paths")
	}
	if _, err := hex.DecodeString(opts.BaselineSHA256); err != nil {
		return nil, nil, errors.New("invalid baseline SHA-256")
	}
	if strings.EqualFold(filepath.Clean(filepath.Dir(opts.BaselineDisk)), filepath.Clean(opts.Root)) || strings.HasPrefix(strings.ToLower(filepath.Clean(opts.BaselineDisk)), strings.ToLower(filepath.Clean(opts.Root))+string(filepath.Separator)) {
		return nil, nil, errors.New("baseline must be outside disposable storage")
	}
	if _, err := os.Stat(opts.Root); errors.Is(err, os.ErrNotExist) {
		if err = protectNewRoot(opts.Root); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}
	// A user-writable parent could replace even a correctly protected root.
	if err := checkProtectedChain(opts.Root); err != nil {
		return nil, nil, err
	}
	// The discovery file carries the daemon endpoint and bearer token, and the
	// registry binds the pinned template. A user who could replace either could
	// redirect the broker to another API or template binding.
	registry := filepath.Join(filepath.Dir(opts.Discovery), "vms.cfg")
	for _, native := range []string{opts.Discovery, registry} {
		if err := checkProtectedChain(native); err != nil {
			return nil, nil, fmt.Errorf("native App Sandbox file is not administrator-protected: %w", err)
		}
	}
	lock, err := (control.Files{Dir: opts.Root}).Acquire()
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = lock.Release() }
	records, err := OpenRecords(opts.Root)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	closeLock := cleanup
	cleanup = func() { _ = records.Close(); closeLock() }
	const manifest = "broker.json"
	var previous BrokerOptions
	if err = records.read(manifest, &previous); errors.Is(err, os.ErrNotExist) {
		all, listErr := records.All()
		if listErr != nil || len(all) != 0 {
			cleanup()
			return nil, nil, errors.New("unbound broker root contains records")
		}
		if err = records.write(manifest, opts); err != nil {
			cleanup()
			return nil, nil, err
		}
	} else if err != nil || previous != opts {
		cleanup()
		return nil, nil, errors.New("broker root belongs to another configuration")
	}
	api, err := Open(ctx, opts.Discovery)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	closeRecords := cleanup
	cleanup = func() { api.Close(); closeRecords() }
	v, err := api.Version(ctx)
	if err != nil || v.HostOS != "Windows" || v.Version != "0.1.9" {
		cleanup()
		return nil, nil, errors.New("native broker requires App Sandbox 0.1.9 on Windows")
	}
	if err = checkTemplateBinding(registry, opts.Baseline, opts.BaselineDisk); err != nil {
		cleanup()
		return nil, nil, err
	}
	if err = checkProtectedChain(opts.BaselineDisk); err != nil {
		cleanup()
		return nil, nil, err
	}
	f, err := os.Open(opts.BaselineDisk)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	_ = f.Close()
	if err != nil || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), opts.BaselineSHA256) {
		cleanup()
		return nil, nil, errors.New("pinned baseline hash differs")
	}
	baseline, err := os.Stat(opts.BaselineDisk)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	checkBaseline := func(ctx context.Context) error {
		if err := checkTemplateBinding(registry, opts.Baseline, opts.BaselineDisk); err != nil {
			return err
		}
		current, err := os.Stat(opts.BaselineDisk)
		if err != nil || !os.SameFile(baseline, current) || current.Size() != baseline.Size() || !current.ModTime().Equal(baseline.ModTime()) {
			return errors.New("pinned template identity changed")
		}
		templates, err := api.Templates(ctx)
		if err != nil {
			return err
		}
		count := 0
		for _, template := range templates {
			if strings.EqualFold(template.Name, opts.Baseline) && template.OSType == "Windows" {
				count++
			}
		}
		if count != 1 {
			return errors.New("pinned Windows template unavailable")
		}
		return nil
	}
	if err = checkBaseline(ctx); err != nil {
		cleanup()
		return nil, nil, err
	}
	network, err := newWindowsNetwork(records)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	engine, err := NewEngine(EngineOptions{ControllerID: opts.ControllerID, Baseline: opts.Baseline, User: opts.GuestUser, MaxCPU: opts.MaxCPU, MaxMemoryMB: opts.MaxMemoryMB, MaxDiskGB: opts.MaxDiskGB, MaxInstances: opts.MaxInstances}, api, network, records, checkBaseline)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return engine, cleanup, nil
}
func checkTemplateBinding(path, name, disk string) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.New("cannot verify native template registry")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes {
		return errors.New("native template registry exceeds bound or is unreadable")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 65536)
	section := ""
	templateName := ""
	templateDisk := ""
	templateOS := ""
	count := 0
	matchingNames := 0
	finish := func() {
		if section == "[Template]" && strings.EqualFold(templateName, name) {
			matchingNames++
			if strings.EqualFold(filepath.Clean(templateDisk), filepath.Clean(disk)) && templateOS == "Windows" {
				count++
			}
		}
	}
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if strings.HasPrefix(line, "[") {
			finish()
			section = line
			templateName = ""
			templateDisk = ""
			templateOS = ""
			continue
		}
		if section != "[Template]" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch key {
		case "Name":
			templateName = value
		case "VhdxPath":
			templateDisk = value
		case "OsType":
			templateOS = value
		}
	}
	finish()
	if scanner.Err() != nil || count != 1 || matchingNames != 1 {
		return errors.New("native template storage binding differs")
	}
	return nil
}

// PrivateGuestDirectory creates a normal-user staging directory with explicit
// Windows ACLs before any JIT bytes are written. Windows ignores Unix mode bits.
func PrivateGuestDirectory(base string) (string, error) {
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

// WindowsTransportPaths resolves system OpenSSH instead of an ambient PATH.
func WindowsTransportPaths() (ssh, scp, key string, err error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return "", "", "", err
	}
	base := os.Getenv("ProgramData")
	if base == "" {
		return "", "", "", errors.New("ProgramData is unavailable")
	}
	return filepath.Join(system, "OpenSSH", "ssh.exe"), filepath.Join(system, "OpenSSH", "scp.exe"), filepath.Join(base, "AppSandbox", "ssh", "id_appsandbox"), nil
}
