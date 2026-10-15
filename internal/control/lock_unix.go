//go:build !windows

package control

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Lock is an exclusive daemon lock held for the process lifetime.
type Lock struct {
	f *os.File
}

// Acquire takes the exclusive flock in the state directory, or fails with
// ErrAlreadyRunning. Only one daemon may manage the state and poll GitHub.
// The kernel releases the lock when the process exits, including a crash.
func (f Files) Acquire() (*Lock, error) {
	return acquireRetrying(f.tryAcquire)
}

func (f Files) tryAcquire() (*Lock, error) {
	path := f.lockPath()
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(fh.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = fh.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return &Lock{f: fh}, nil
}

// Release drops the lock.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	return l.f.Close()
}

// probeLock reports whether another open file description holds the daemon
// lock exclusively. It takes a nonblocking shared flock and drops it at once;
// flock locks belong to the open file description, so a probe inside the
// daemon's own process neither succeeds nor releases the daemon's lock.
func (f Files) probeLock() (bool, error) {
	fh, err := os.Open(f.lockPath())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = fh.Close() }()
	if err := syscall.Flock(int(fh.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}
