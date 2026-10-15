//go:build !windows

package control

import (
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func holdShared(t *testing.T, f Files) func() {
	t.Helper()
	fh, err := os.Open(f.lockPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(fh.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	return func() { _ = fh.Close() }
}

// After a crash the PID file can name an unrelated process. Wake must signal
// only while the daemon lock is held.
func TestWakeSignalsOnlyLockHolder(t *testing.T) {
	f := Files{Dir: t.TempDir()}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, WakeSignal)
	defer signal.Stop(sigs)
	if err := os.WriteFile(filepath.Join(f.Dir, "daemon.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if woke, err := f.Wake(); err != nil || woke {
		t.Fatalf("stale PID woken: %v %v", woke, err)
	}
	lock, err := f.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if woke, err := f.Wake(); err != nil || woke {
		t.Fatalf("stale PID with released lock woken: %v %v", woke, err)
	}
	select {
	case <-sigs:
		t.Fatal("signal sent to a process that holds no daemon lock")
	case <-time.After(100 * time.Millisecond):
	}

	lock, err = f.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()
	if woke, err := f.Wake(); err != nil || !woke {
		t.Fatalf("lock holder not woken: %v %v", woke, err)
	}
	select {
	case <-sigs:
	case <-time.After(2 * time.Second):
		t.Fatal("lock holder received no wake signal")
	}
	if err := f.RemovePID(); err != nil {
		t.Fatal(err)
	}
	if woke, err := f.Wake(); err != nil || !woke {
		t.Fatalf("holder before PID write: %v %v", woke, err)
	}
}
