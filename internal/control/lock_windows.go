//go:build windows

package control

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Lock is an exclusive daemon lock held for the process lifetime.
type Lock struct {
	f *os.File
}

// Acquire takes a nonblocking kernel byte-range lock. Windows releases it on
// process exit, including a crash before the PID file is written. The file
// remains in place: unlinking it would permit two different lock inodes.
func (f Files) Acquire() (*Lock, error) {
	return acquireRetrying(f.tryAcquire)
}

func (f Files) tryAcquire() (*Lock, error) {
	fh, err := os.OpenFile(f.lockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	err = windows.LockFileEx(windows.Handle(fh.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if err != nil {
		_ = fh.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrAlreadyRunning
		}
		return nil, err
	}
	return &Lock{f: fh}, nil
}

// Release drops the lock. It unlocks explicitly: Windows may release a
// closed handle's lock only after a delay.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, &windows.Overlapped{})
	return errors.Join(err, l.f.Close())
}

// probeLock reports whether another handle holds the daemon lock. It takes a
// nonblocking shared byte-range lock and unlocks it explicitly before closing:
// release on close may be delayed, which would make a starting daemon wait.
func (f Files) probeLock() (bool, error) {
	fh, err := os.OpenFile(f.lockPath(), os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = fh.Close() }()
	handle := windows.Handle(fh.Fd())
	err = windows.LockFileEx(handle, windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, windows.UnlockFileEx(handle, 0, 1, 0, &windows.Overlapped{})
}
