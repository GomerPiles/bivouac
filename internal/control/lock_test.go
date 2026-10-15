package control

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// A liveness probe that happens to hold its shared lock while a daemon starts
// must not make that daemon exit as a duplicate.
func TestAcquireOutlastsConcurrentProbe(t *testing.T) {
	f := Files{Dir: t.TempDir()}
	first, err := f.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	probe := holdShared(t, f)
	released := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		probe()
		close(released)
	}()
	lock, err := f.Acquire()
	<-released
	if err != nil {
		t.Fatalf("daemon start lost to a probe: %v", err)
	}
	if !f.Alive() {
		t.Fatal("held lock reported dead")
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if f.Alive() {
		t.Fatal("released lock reported alive")
	}
}

func TestAcquireRefusesSecondOwner(t *testing.T) {
	f := Files{Dir: t.TempDir()}
	first, err := f.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Release() }()
	started := time.Now()
	if second, err := f.Acquire(); !errors.Is(err, ErrAlreadyRunning) {
		_ = second.Release()
		t.Fatalf("second owner: %v", err)
	}
	if time.Since(started) < lockWait {
		t.Fatal("contended lock gave up before the probe window")
	}
}

func TestStalePIDWithoutLockIsNotAlive(t *testing.T) {
	f := Files{Dir: t.TempDir()}
	// Our own PID stands in for an unrelated live process after a reboot.
	if err := os.WriteFile(filepath.Join(f.Dir, "daemon.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if f.Alive() {
		t.Fatal("stale PID without lock file reported alive")
	}
	lock, err := f.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if f.Alive() {
		t.Fatal("stale PID with released lock reported alive")
	}
}
