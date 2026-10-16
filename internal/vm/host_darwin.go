package vm

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Clone copies baseline to name with APFS clonefile (copy-on-write, tens of
// milliseconds) and gives the copy a fresh MAC address. The copy is staged
// under a hidden name and renamed into place, so a crash never leaves a
// half-copied VM under name.
func (h Home) Clone(baseline, name string) error {
	if err := validName(baseline); err != nil {
		return err
	}
	if err := validName(name); err != nil {
		return err
	}
	src, dst := h.Dir(baseline), h.Dir(name)
	if _, err := ReadConfig(src); err != nil {
		return fmt.Errorf("baseline %q: %w", baseline, err)
	}
	// A running baseline's disk is not crash-consistent.
	if pid, err := Holder(src); err != nil || pid != 0 {
		return fmt.Errorf("baseline %q is running", baseline)
	}
	for _, f := range []string{DiskFile, NVRAMFile} {
		if _, err := os.Stat(filepath.Join(src, f)); err != nil {
			return fmt.Errorf("baseline %q lacks %s (stacked disks are unsupported)", baseline, f)
		}
	}
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("VM %q already exists", name)
	}
	stage := filepath.Join(filepath.Dir(dst), "."+name+".clone")
	if err := os.RemoveAll(stage); err != nil {
		return err
	}
	if err := os.Mkdir(stage, 0o700); err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(stage)
		}
	}()
	for _, f := range []string{DiskFile, NVRAMFile} {
		if err := unix.Clonefile(filepath.Join(src, f), filepath.Join(stage, f), unix.CLONE_NOFOLLOW); err != nil {
			return fmt.Errorf("clone %s: %w", f, err)
		}
	}
	config, err := os.ReadFile(filepath.Join(src, ConfigFile))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, ConfigFile), config, 0o600); err != nil {
		return err
	}
	mac, err := randomMAC()
	if err != nil {
		return err
	}
	if err := updateConfig(stage, map[string]any{"macAddress": mac}); err != nil {
		return err
	}
	if err := unix.RenamexNp(stage, dst, unix.RENAME_EXCL); err != nil {
		return fmt.Errorf("move clone into place: %w", err)
	}
	ok = true
	return nil
}

// Resize sets CPU count and memory (MiB) of a stopped VM. Zero keeps a value.
func (h Home) Resize(name string, cpu, memoryMB int) error {
	if err := validName(name); err != nil {
		return err
	}
	dir := h.Dir(name)
	// Holding the lock across the rewrite keeps a helper from starting on
	// the old file; the rename then leaves no lock behind on a running VM.
	lock, err := Acquire(dir)
	if err != nil {
		return fmt.Errorf("VM %q must be stopped before resizing: %w", name, err)
	}
	defer func() { _ = lock.Release() }()
	data, err := lock.raw()
	if err != nil {
		return err
	}
	c, err := parseConfig(data)
	if err != nil {
		return err
	}
	fields := map[string]any{}
	if cpu > 0 {
		if cpu < c.CPUCountMin {
			return fmt.Errorf("VM %q needs at least %d CPUs", name, c.CPUCountMin)
		}
		fields["cpuCount"] = cpu
	}
	if memoryMB > 0 {
		bytes := uint64(memoryMB) << 20
		if bytes < c.MemorySizeMin {
			return fmt.Errorf("VM %q needs at least %d MiB of memory", name, c.MemorySizeMin>>20)
		}
		fields["memorySize"] = bytes
	}
	if len(fields) == 0 {
		return nil
	}
	// Not updateConfig: reopening config.json here would drop the lock.
	return rewriteConfig(dir, data, fields)
}

// Lock is the running VM's claim on its directory: an fcntl write lock on
// config.json, the same lock Tart takes, so `tart list` reports the VM as
// running and Tart refuses to start or delete it.
//
// POSIX releases fcntl locks when the process closes any descriptor of the
// file, so the holder must never open config.json again while it runs. In
// a process that holds a Lock (Resize), Holder or List on the same VM
// releases it too; the helper holds its lock alone in its own process.
type Lock struct{ f *os.File }

// Acquire takes dir's lock or fails if another process holds it.
func Acquire(dir string) (*Lock, error) {
	f, err := os.OpenFile(filepath.Join(dir, ConfigFile), os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0}
	if err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lk); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EACCES) {
			return nil, errors.New("VM is already running")
		}
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Release drops the lock.
func (l *Lock) Release() error { return l.f.Close() }

// Config reads config.json through the locked descriptor, so the file read
// is the one locked and the lock survives the read.
func (l *Lock) Config() (Config, error) {
	data, err := l.raw()
	if err != nil {
		return Config{}, err
	}
	return parseConfig(data)
}

func (l *Lock) raw() ([]byte, error) {
	return io.ReadAll(io.NewSectionReader(l.f, 0, 1<<20))
}

// Holder returns the pid holding dir's lock, or 0 when the VM is stopped or
// absent. It must not be called by the lock holder itself.
func Holder(dir string) (int, error) {
	f, err := os.Open(filepath.Join(dir, ConfigFile))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0}
	if err := unix.FcntlFlock(f.Fd(), unix.F_GETLK, &lk); err != nil {
		return 0, err
	}
	if lk.Type == unix.F_UNLCK {
		return 0, nil
	}
	return int(lk.Pid), nil
}

// List returns every VM directory under h with its running state. Staging
// directories (hidden names) are skipped. A VM whose lock cannot be read is
// reported running, so it still counts against the host limit and is never
// treated as stopped; one unreadable directory does not hide the others.
func (h Home) List() ([]Entry, error) {
	entries, err := os.ReadDir(filepath.Join(string(h), "vms"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		pid, err := Holder(h.Dir(e.Name()))
		out = append(out, Entry{Name: e.Name(), Running: err != nil || pid != 0})
	}
	return out, nil
}

// Delete removes a stopped VM directory. Callers check ownership first.
func (h Home) Delete(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	dir := h.Dir(name)
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return fs.ErrNotExist
	}
	pid, err := Holder(dir)
	if err != nil {
		return err
	}
	if pid != 0 {
		return fmt.Errorf("VM %q is running", name)
	}
	return os.RemoveAll(dir)
}
