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

// Clone copies baseline to name with APFS clonefile (copy-on-write,
// milliseconds) and writes the clone's manifest with a fresh MAC address and
// its own CPU and memory. The copy is staged under a hidden name and renamed
// into place, so a crash never leaves a half-copied VM under name.
func (h Store) Clone(baseline, name string, opts CloneOptions) error {
	if err := validName(baseline); err != nil {
		return err
	}
	src := h.Dir(baseline)
	m, err := ReadManifest(src)
	if err != nil {
		return fmt.Errorf("baseline %q: %w", baseline, err)
	}
	// A running baseline's disk is not crash-consistent.
	if pid, err := Holder(src); err != nil || pid != 0 {
		return fmt.Errorf("baseline %q is running", baseline)
	}
	if opts.CPU > 0 {
		if opts.CPU < m.CPUMin {
			return fmt.Errorf("baseline %q needs at least %d CPUs", baseline, m.CPUMin)
		}
		m.CPU = opts.CPU
	}
	if opts.MemoryMiB > 0 {
		if uint64(opts.MemoryMiB) < m.MemoryMinMiB {
			return fmt.Errorf("baseline %q needs at least %d MiB of memory", baseline, m.MemoryMinMiB)
		}
		m.MemoryMiB = uint64(opts.MemoryMiB)
	}
	if m.MAC, err = randomMAC(); err != nil {
		return err
	}
	return h.stage(src, name, m)
}

// Import copies the Tart-format VM in src (config.json, disk.img,
// nvram.bin) into the store as name, with clonefile when src is on the
// store's volume and a full copy otherwise. The manifest records guest,
// which the caller vouches for: the installed guest agent's version, the
// runner directory, and passwordless sudo.
func (h Store) Import(src, name string, guest Guest) error {
	c, err := readTartConfig(src)
	if err != nil {
		return err
	}
	m, err := c.manifest(guest)
	if err != nil {
		return err
	}
	// Tart takes the same fcntl lock on its config.json while it runs a VM.
	if pid, err := holderOf(filepath.Join(src, tartConfigFile)); err != nil || pid != 0 {
		return fmt.Errorf("%s is running", src)
	}
	return h.stage(src, name, m)
}

func readTartConfig(dir string) (tartConfig, error) {
	data, err := os.ReadFile(filepath.Join(dir, tartConfigFile))
	if err != nil {
		return tartConfig{}, err
	}
	return parseTartConfig(data)
}

// stage copies src's disk and NVRAM, writes m, and renames the result to
// name.
func (h Store) stage(src, name string, m Manifest) error {
	if err := validName(name); err != nil {
		return err
	}
	for _, f := range []string{DiskFile, NVRAMFile} {
		if _, err := os.Stat(filepath.Join(src, f)); err != nil {
			return fmt.Errorf("%s lacks %s (stacked disks are unsupported)", src, f)
		}
	}
	dst := h.Dir(name)
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("VM %q already exists", name)
	}
	if err := os.MkdirAll(string(h), 0o700); err != nil {
		return err
	}
	stage := filepath.Join(string(h), "."+name+".clone")
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
		if err := copyFile(filepath.Join(src, f), filepath.Join(stage, f)); err != nil {
			return fmt.Errorf("copy %s: %w", f, err)
		}
	}
	if err := WriteManifest(stage, m); err != nil {
		return err
	}
	if err := unix.RenamexNp(stage, dst, unix.RENAME_EXCL); err != nil {
		return fmt.Errorf("move %q into place: %w", name, err)
	}
	ok = true
	return nil
}

// copyFile clones src to dst, or copies it when they are on different
// volumes (EXDEV) or the volume cannot clone (ENOTSUP).
func copyFile(src, dst string) error {
	err := unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW)
	if err == nil || !errors.Is(err, unix.EXDEV) && !errors.Is(err, unix.ENOTSUP) {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// Lock is the running VM's claim on its directory: an fcntl write lock on
// its manifest, whose holder's pid identifies the helper.
//
// POSIX releases fcntl locks when the process closes any descriptor of the
// file, so the holder must never open the manifest again while it runs; the
// helper holds its lock alone in its own process. A manifest is never
// rewritten once its VM is in place.
type Lock struct{ f *os.File }

// Acquire takes dir's lock or fails if another process holds it.
func Acquire(dir string) (*Lock, error) {
	f, err := os.OpenFile(filepath.Join(dir, ManifestFile), os.O_RDWR, 0)
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

// Manifest reads the manifest through the locked descriptor, so the file
// read is the one locked and the lock survives the read.
func (l *Lock) Manifest() (Manifest, error) {
	data, err := io.ReadAll(io.NewSectionReader(l.f, 0, 1<<20))
	if err != nil {
		return Manifest{}, err
	}
	return parseManifest(data)
}

// Holder returns the pid holding dir's lock, or 0 when the VM is stopped or
// absent. It must not be called by the lock holder itself.
func Holder(dir string) (int, error) { return holderOf(filepath.Join(dir, ManifestFile)) }

func holderOf(path string) (int, error) {
	f, err := os.Open(path)
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

// List returns every VM directory in the store with its running state.
// Hidden entries (staging directories and the socket directory) are skipped. A VM whose lock cannot be read is
// reported running, so it still counts against the host limit and is never
// treated as stopped; one unreadable directory does not hide the others.
func (h Store) List() ([]Entry, error) {
	entries, err := os.ReadDir(string(h))
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
func (h Store) Delete(name string) error {
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
	// A helper that was killed leaves its socket behind.
	if socket, err := h.SocketPath(name); err == nil {
		_ = os.Remove(socket)
	}
	if socket, err := h.CacheSocketPath(name); err == nil {
		if info, err := os.Lstat(socket); err == nil && info.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(socket)
		}
	}
	if socket, err := h.RevocationSocketPath(name); err == nil {
		if info, err := os.Lstat(socket); err == nil && info.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(socket)
		}
	}
	return os.RemoveAll(dir)
}
