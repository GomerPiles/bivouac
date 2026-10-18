//go:build linux

package crosvm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Image preparation is explicit guest-only factory work, after owned bootstrap
// and before JIT delivery. It never runs from ordinary readiness or registration.
func rootPath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || !directory && !info.Mode().IsRegular() {
		return errors.New("image factory path is not root-owned and protected")
	}
	return nil
}
func fixedImageFile(path string, data []byte, mode os.FileMode) error {
	if err := rootPath(filepath.Dir(path), true); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return errors.New("image factory destination already exists or is unavailable")
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

const sshHostKeyUnit = `[Unit]
Description=Generate fresh SSH host keys for disposable CI guests
Before=ssh.service
[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A
RemainAfterExit=yes
`
const sshHostKeyDependency = `[Unit]
Requires=bivouac-ssh-hostkeys.service
After=bivouac-ssh-hostkeys.service
`

func prepareLinuxImage(ctx context.Context, self string, input io.Reader, out io.Writer) (result error) {
	if os.Getuid() != 0 {
		return errors.New("image preparation requires explicit guest root invocation")
	}
	stage := uint32(1)
	defer func() {
		if result != nil {
			result = json.NewEncoder(out).Encode(PreparedLinuxImage{FailedStage: stage})
		}
	}()
	var request ImagePreparationRequest
	d := json.NewDecoder(io.LimitReader(input, 4097))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF || !digest(request.HelperSHA256) {
		return errors.New("invalid bounded image preparation request")
	}
	stage = 2
	cfg, err := guestConfig()
	if err != nil {
		return err
	}
	if cfg.Name != request.Name || cfg.ControllerID != request.ControllerID || cfg.BootID != request.BootID {
		return errors.New("image factory bootstrap identity differs")
	}
	stage = 3
	entries, err := os.ReadDir(guestRoot)
	if err != nil {
		return err
	}
	if len(entries) != 2 {
		return errors.New("image factory requires fresh bootstrap only")
	}
	for _, entry := range entries {
		if entry.Name() != "config.json" && entry.Name() != "helper" {
			return errors.New("image factory refuses job or credential state")
		}
	}
	stage = 4
	if err = sanitizeRunnerFactory(cfg.RunnerDir); err != nil {
		return err
	}

	// Pin and hash this exact public helper before installing it in the image.
	stage = 5
	source, err := os.Open(self)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(source, 128<<20+1))
	if err != nil || n > 128<<20 || hex.EncodeToString(h.Sum(nil)) != request.HelperSHA256 {
		return errors.New("image factory helper pin differs")
	}
	if _, err = source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	stage = 6
	for _, path := range []string{"/", "/usr", "/usr/local", "/etc", "/etc/systemd", "/etc/systemd/system", "/etc/ssh", "/var", "/var/lib", "/var/lib/systemd", "/var/lib/dbus"} {
		if err = rootPath(path, true); err != nil {
			return err
		}
	}
	// Refuse recapture; this factory is for new, unenrolled disposable builds.
	if _, err = os.Lstat("/etc/bivouac/prepared-image.json"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("prepared image marker exists or cannot be inspected")
	}
	stage = 7
	for _, path := range []string{"/usr/local/libexec", "/etc/bivouac", "/etc/systemd/system/ssh.service.d"} {
		// #nosec G301 -- Public guest helper/config directories need traversal by the dedicated non-root runner; only root may mutate.
		if err = os.Mkdir(path, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err = rootPath(path, true); err != nil {
			return err
		}
	}
	stage = 8
	unit, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "--property=LoadState", "--value", "ssh.service").Output()
	if err != nil || strings.TrimSpace(string(unit)) != "loaded" {
		return errors.New("image factory needs the supported ssh.service")
	}
	stage = 9
	if _, err = persistentPublicDNS(ctx); err != nil {
		return err
	}
	stage = 10
	// #nosec G302 -- The public root-owned helper must be executable by the dedicated non-root runner.
	destination, err := os.OpenFile(preparedHelper, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return errors.New("prepared helper already exists or cannot be installed")
	}
	_, err = io.Copy(destination, source)
	if err == nil {
		err = destination.Sync()
	}
	if err = errors.Join(err, destination.Close()); err != nil {
		return err
	}
	stage = 11
	if err = fixedImageFile("/etc/systemd/system/bivouac-ssh-hostkeys.service", []byte(sshHostKeyUnit), 0644); err != nil {
		return err
	}
	if err = fixedImageFile("/etc/systemd/system/ssh.service.d/bivouac-hostkeys.conf", []byte(sshHostKeyDependency), 0644); err != nil {
		return err
	}
	if exec.CommandContext(ctx, "/usr/bin/systemctl", "daemon-reload").Run() != nil {
		return errors.New("image factory unit reload failed")
	}
	// Stop seed persistence before deleting the factory seed; shutdown must not
	// write it back. The normal service runs again on each subsequent cold boot.
	stage = 12
	if exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", "systemd-random-seed.service").Run() != nil {
		return errors.New("image factory random-seed shutdown failed")
	}
	stage = 13
	for _, path := range []string{"/var/lib/systemd/random-seed", "/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_rsa_key.pub", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ecdsa_key.pub", "/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ed25519_key.pub"} {
		if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
			continue
		}
		if err = rootPath(path, false); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	stage = 14
	if err = rootPath("/etc/machine-id", false); err != nil {
		return err
	}
	// Empty (rather than absent) requests a new ID without another full first boot.
	if err = os.Truncate("/etc/machine-id", 0); err != nil {
		return err
	}
	stage = 15
	dbusID := "/var/lib/dbus/machine-id"
	if info, e := os.Lstat(dbusID); e == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			target, e := os.Readlink(dbusID)
			if e != nil || filepath.Clean(filepath.Join(filepath.Dir(dbusID), target)) != "/etc/machine-id" && target != "/etc/machine-id" {
				return errors.New("unexpected D-Bus machine-id link")
			}
		} else {
			if err = rootPath(dbusID, false); err != nil {
				return err
			}
			if err = os.Remove(dbusID); err != nil {
				return err
			}
			if err = os.Symlink("/etc/machine-id", dbusID); err != nil {
				return err
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	// Only the two exact bootstrap files proven above are removed, never a tree.
	stage = 16
	for _, name := range []string{"config.json", "helper"} {
		if err = os.Remove(filepath.Join(guestRoot, name)); err != nil {
			return err
		}
	}
	if err = os.Remove(guestRoot); err != nil {
		return err
	}
	stage = 17
	report := PreparedLinuxImage{HelperSHA256: request.HelperSHA256, RunnerUnconfigured: true, DNSPrepared: true, MachineIDCleared: true, SSHHostKeysRemoved: true}
	b, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if err = fixedImageFile("/etc/bivouac/prepared-image.json", b, 0644); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}

// Fixed numeric boot observations avoid retaining guest service names or logs.
func linuxBootReport(ctx context.Context, out io.Writer) error {
	if _, err := guestConfig(); err != nil {
		return err
	}
	report := map[string]uint64{}
	for _, entry := range []struct{ key, unit string }{{"ssh_active_us", "ssh.service"}, {"docker_active_us", "docker.service"}, {"network_wait_active_us", "NetworkManager-wait-online.service"}, {"cloud_init_active_us", "cloud-init.service"}} {
		b, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "--property=ActiveEnterTimestampMonotonic", "--value", entry.unit).Output()
		if err != nil || len(b) > 32 {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err == nil {
			report[entry.key] = value
		}
	}
	return json.NewEncoder(out).Encode(report)
}
