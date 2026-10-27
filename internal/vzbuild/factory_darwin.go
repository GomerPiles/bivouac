package vzbuild

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/vm"
	"golang.org/x/sys/unix"
)

type factory struct {
	store vm.Store
	dir   string
	lock  *os.File
	// stop is replaceable in offline tests; production always uses HelperPID.
	stop     func(context.Context, string) error
	daemon   control.Files
	warnings []error
	logs     string
	archived []string
}

func openFactory(store string, daemon control.Files) (*factory, error) {
	if !filepath.IsAbs(store) {
		return nil, errors.New("factory store must be absolute")
	}
	if err := vm.Store(store).CheckSocketPath(); err != nil {
		return nil, err
	}
	dir := filepath.Join(store, factoryDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if _, err := fileIdentity(dir); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "builder.lock")
	if info, err := os.Lstat(lockPath); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("unrecognized factory lock file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("another baseline builder holds the factory lock")
	}
	return &factory{store: vm.Store(store), dir: dir, lock: f, stop: stopFactoryVM, daemon: daemon}, nil
}
func fileIdentity(path string) (identity, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return identity{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return identity{}, errors.New("factory path is not a plain directory")
	}
	return identity{Device: uint64(st.Dev), Inode: st.Ino}, nil //nolint:gosec // dev_t is an opaque identity, including its sign bit.
}
func identityOrAbsent(path string) (identity, error) {
	id, err := fileIdentity(path)
	if errors.Is(err, os.ErrNotExist) {
		return identity{}, nil
	}
	return id, err
}
func stopFactoryVM(ctx context.Context, dir string) error {
	for _, step := range []struct {
		signal unix.Signal
		bound  time.Duration
	}{{unix.SIGTERM, 10 * time.Second}, {unix.SIGKILL, 10 * time.Second}} {
		pid, err := vm.HelperPID(dir)
		if err != nil || pid == 0 {
			return err
		}
		if err := unix.Kill(pid, step.signal); err != nil && !errors.Is(err, unix.ESRCH) {
			return errors.New("cannot stop proven factory helper")
		}
		deadline := time.Now().Add(step.bound)
		for time.Now().Before(deadline) {
			pid, err := vm.HelperPID(dir)
			if err != nil {
				return err
			}
			if pid == 0 {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return errors.New("factory helper did not release its lock")
}

// removeVM archives the launch log only when it explains a failure or recovery.
func (f *factory) removeVM(ctx context.Context, name string, want identity, archive bool) error {
	path := f.store.Dir(name)
	got, err := identityOrAbsent(path)
	if err != nil {
		return err
	}
	if got.empty() {
		return nil
	}
	if want.empty() {
		if err := expectedFactoryContents(path); err != nil {
			return err
		}
		want = got
	}
	if got != want {
		return errors.New("unrecognized factory directory; retained for inspection")
	}
	if err := f.stop(ctx, path); err != nil {
		return err
	}
	// Recheck identity after waiting; do not remove a replacement directory.
	if got, err = fileIdentity(path); err != nil || got != want {
		return errors.New("factory identity changed during cleanup")
	}
	if archive {
		archived, err := archiveLaunchLog(path, f.logs, strings.TrimPrefix(strings.TrimPrefix(name, ".build-"), ".gate-"), strings.HasPrefix(name, ".gate-"))
		if err != nil {
			return err
		}
		if archived != "" {
			f.archived = append(f.archived, archived)
		}
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	for _, socket := range []func(string) (string, error){f.store.SocketPath, f.store.CacheSocketPath, f.store.RevocationSocketPath} {
		if path, err := socket(name); err == nil {
			if i, err := os.Lstat(path); err == nil && i.Mode()&os.ModeSocket != 0 {
				_ = os.Remove(path)
			}
		}
	}
	return syncDir(string(f.store))
}

// Recovery retains unrecognized state and reports it without blocking an
// unrelated new build. Recognized records are recovered independently.
func (f *factory) recover(ctx context.Context) error {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return err
	}
	recorded := map[string]bool{}
	var records []factoryRecord
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.Name() == "builder.lock" {
			continue
		}
		if strings.HasPrefix(e.Name(), ".record-") {
			if err := removeFactoryTemp(filepath.Join(f.dir, e.Name()), 8193); err != nil {
				f.warnings = append(f.warnings, err)
			}
			continue
		}
		if e.IsDir() || e.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(e.Name(), ".json") {
			f.warnings = append(f.warnings, errors.New("unrecognized factory record retained"))
			continue
		}
		r, err := readRecord(filepath.Join(f.dir, e.Name()))
		if err != nil || e.Name() != r.ID+".json" {
			f.warnings = append(f.warnings, errors.New("unrecognized factory record retained"))
			continue
		}
		records = append(records, r)
		recorded[r.BuildDir] = true
		recorded[r.GateDir] = true
	}
	entries, err = os.ReadDir(string(f.store))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if (strings.HasPrefix(e.Name(), ".build-") || strings.HasPrefix(e.Name(), ".gate-")) && !recorded[e.Name()] {
			f.warnings = append(f.warnings, errors.New("unrecorded factory directory retained"))
		}
	}
	for _, r := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := f.recoverRecord(ctx, r); err != nil {
			f.warnings = append(f.warnings, err)
		}
	}
	return syncDir(f.dir)
}
func expectedFactoryContents(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	allowed := map[string]bool{vm.DiskFile: true, vm.NVRAMFile: true, vm.ManifestFile: true, "seed.iso": true, "receipt.img": true, "launch.log": true}
	for _, e := range entries {
		var st unix.Stat_t
		if !allowed[e.Name()] || unix.Lstat(filepath.Join(path, e.Name()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int64(st.Uid) != int64(os.Geteuid()) {
			return errors.New("unrecognized factory contents retained")
		}
	}
	return nil
}
func removeFactoryTemp(path string, bound int64) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int64(st.Uid) != int64(os.Geteuid()) || st.Size < 0 || st.Size > bound {
		return errors.New("unrecognized factory temporary file retained")
	}
	return os.Remove(path)
}
func (f *factory) recoverInputs(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".input-") {
			if err := removeFactoryTemp(filepath.Join(dir, e.Name()), 2<<30); err != nil {
				f.warnings = append(f.warnings, err)
			}
		}
	}
	return syncDir(dir)
}

// advisoryTarget runs before any input/download or build work. Publication
// repeats it while holding the daemon lock for the complete replacement.
func (f *factory) advisoryTarget(name string, replace bool) error {
	if !replace {
		if _, err := os.Lstat(f.store.Dir(name)); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		return errors.New("baseline target already exists; factory-built targets require --replace")
	}
	lock, err := f.daemon.Acquire()
	if err != nil {
		return errors.New("--replace requires this home's daemon to be stopped")
	}
	defer func() { _ = lock.Release() }()
	_, err = f.replaceGuard(name)
	return err
}
func (f *factory) recoverRecord(ctx context.Context, r factoryRecord) error {
	var daemonLock *control.Lock
	if !r.Old.empty() {
		// A crash during replacement may leave a retired baseline in staging. Hold
		// the same daemon lock as publication until its identity-checked removal.
		var err error
		daemonLock, err = f.daemon.Acquire()
		if err != nil {
			return errors.New("stop this home's daemon before recovering replacement state")
		}
		defer func() { _ = daemonLock.Release() }()
	}
	buildIdentity := r.Build
	if r.Phase == "swap" || r.Phase == "publish" || r.Phase == "published" {
		target, err := identityOrAbsent(f.store.Dir(r.Target))
		if err != nil {
			return err
		}
		switch {
		case target == r.New:
			// Swap may have completed before the next journal fsync. Only the old
			// identity can be deleted at the staging path; target is never deleted.
			buildIdentity = r.Old
		case !r.Old.empty() && target == r.Old:
			buildIdentity = r.New
		case r.Old.empty():
			buildIdentity = r.New
		default:
			return errors.New("factory publication identities are ambiguous; retained for inspection")
		}
	}
	if err := f.removeVM(ctx, r.GateDir, r.Gate, true); err != nil {
		return err
	}
	if err := f.removeVM(ctx, r.BuildDir, buildIdentity, true); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(f.dir, r.ID+".json")); err != nil {
		return err
	}
	return syncDir(f.dir)
}
func (f *factory) replaceGuard(name string) (identity, error) {
	path := f.store.Dir(name)
	id, err := fileIdentity(path)
	if err != nil {
		return identity{}, err
	}
	m, err := vm.ReadManifest(path)
	if err != nil || m.Build == nil {
		return identity{}, errors.New("--replace requires an existing factory-built baseline; imported baselines are never replaced")
	}
	if pid, err := vm.Holder(path); err != nil || pid != 0 {
		return identity{}, errors.New("cannot replace a locked baseline")
	}
	return id, nil
}
func (f *factory) publish(r *factoryRecord, replace bool) error {
	r.New = r.Build
	r.Phase = "publish"
	var daemonLock *control.Lock
	var err error
	if replace {
		daemonLock, err = f.daemon.Acquire()
		if err != nil {
			return errors.New("--replace requires this home's daemon to be stopped")
		}
		defer func() { _ = daemonLock.Release() }()
		r.Old, err = f.replaceGuard(r.Target)
		if err != nil {
			return err
		}
		r.Phase = "swap"
	}
	if err := writeRecord(f.dir, *r); err != nil {
		return err
	}
	flags := uint32(unix.RENAME_EXCL)
	if replace {
		flags = unix.RENAME_SWAP
	}
	if err := unix.RenamexNp(f.store.Dir(".build-"+r.ID), f.store.Dir(r.Target), flags); err != nil {
		return err
	}
	if err := syncDir(string(f.store)); err != nil {
		return err
	}
	r.Phase = "published"
	if err := writeRecord(f.dir, *r); err != nil {
		return err
	}
	if replace {
		if err := f.removeVM(context.Background(), r.BuildDir, r.Old, false); err != nil {
			return err
		}
	}
	if err := os.Remove(filepath.Join(f.dir, r.ID+".json")); err != nil {
		return err
	}
	return syncDir(f.dir)
}
