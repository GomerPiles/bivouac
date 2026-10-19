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
	"path/filepath"
	"strings"

	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/winhost"
	"golang.org/x/sys/windows"
)

func protectNewRoot(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) == filepath.VolumeName(path)+string(filepath.Separator) || strings.HasPrefix(path, `\\`) {
		return errors.New("broker root must be a dedicated local absolute directory")
	}
	if err := winhost.CheckProtectedParents(path); err != nil {
		return err
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
	return winhost.CheckProtected(path)
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
	if err := winhost.CheckProtected(opts.Root); err != nil {
		return nil, nil, err
	}
	// The discovery file carries the daemon endpoint and bearer token, and the
	// registry binds the pinned template. A user who could replace either could
	// redirect the broker to another API or template binding.
	registry := filepath.Join(filepath.Dir(opts.Discovery), "vms.cfg")
	for _, native := range []string{opts.Discovery, registry} {
		if err := winhost.CheckProtected(native); err != nil {
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
	if err = winhost.CheckProtected(opts.BaselineDisk); err != nil {
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

// DefaultSSHKey is App Sandbox's guest SSH private key, which its template
// authorizes for HvSocket SSH.
func DefaultSSHKey() (string, error) {
	base := os.Getenv("ProgramData")
	if base == "" {
		return "", errors.New("ProgramData is unavailable")
	}
	return filepath.Join(base, "AppSandbox", "ssh", "id_appsandbox"), nil
}
