package control

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/windows"
)

func holdShared(t *testing.T, f Files) func() {
	t.Helper()
	fh, err := os.OpenFile(f.lockPath(), os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.LockFileEx(windows.Handle(fh.Fd()), windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		t.Fatal(err)
	}
	return func() { _ = fh.Close() }
}

func TestWindowsLockExcludesSecondOwnerWithoutPID(t *testing.T) {
	f := Files{Dir: t.TempDir()}
	first, err := f.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Release() })
	if second, err := f.Acquire(); !errors.Is(err, ErrAlreadyRunning) {
		if second != nil {
			_ = second.Release()
		}
		t.Fatalf("second owner without PID file: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	first.f = nil
	second, err := f.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsLockReleasedOnProcessExit(t *testing.T) {
	if dir := os.Getenv("BIVOUAC_TEST_LOCK_CHILD"); dir != "" {
		_, err := (Files{Dir: dir}).Acquire()
		if err != nil {
			t.Fatal(err)
		}
		// Exit without Release or a PID file, like a crash during startup.
		os.Exit(0)
	}
	f := Files{Dir: t.TempDir()}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestWindowsLockReleasedOnProcessExit$")
	cmd.Env = append(os.Environ(), "BIVOUAC_TEST_LOCK_CHILD="+f.Dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v %s", err, out)
	}
	lock, err := f.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsAliveRejectsStaleAndInvalidPID(t *testing.T) {
	f := Files{Dir: t.TempDir()}
	for _, pid := range []int{-1, 0, 999999999} {
		if err := os.WriteFile(filepath.Join(f.Dir, "daemon.pid"), []byte(strconv.Itoa(pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		if f.Alive() {
			t.Fatalf("invalid/stale PID %d reported alive", pid)
		}
	}
	if err := os.WriteFile(filepath.Join(f.Dir, "daemon.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if f.Alive() {
		t.Fatal("reused unrelated live PID reported as a daemon")
	}
	lock, err := f.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if !f.Alive() {
		t.Fatal("held manager lock reported dead")
	}
	if running, err := f.Wake(); err != nil || !running {
		t.Fatal("polling daemon reported stopped by mode command")
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if f.Alive() {
		t.Fatal("released manager lock reported alive with stale live PID")
	}
}
