//go:build unix

package vz

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeHost is a fixture host command. Its second argument selects the
// behaviour.
const fakeHost = `#!/bin/sh
case "$2" in
flood) exec /usr/bin/yes ;;
small) echo ok ;;
linger) /bin/sleep 8 & echo started ;;
stderr-flood) /usr/bin/yes >&2 ;;
fail) echo "boom ghs_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
second line" >&2; exit 3 ;;
esac
`

func fixtureCLI(t *testing.T) CLI {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "host-command")
	if err := os.WriteFile(bin, []byte(fakeHost), 0o700); err != nil { // #nosec G306 -- Executable fixture in t.TempDir().
		t.Fatal(err)
	}
	return CLI{Binary: bin}
}

func TestCLIOutputIsBounded(t *testing.T) {
	cli := fixtureCLI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if out, err := output(ctx, cli, []string{"probe", "small"}, statusOutputLimit); err != nil || string(out) != "ok\n" {
		t.Fatalf("small output: %q %v", out, err)
	}
	for _, mode := range []string{"flood", "stderr-flood"} {
		start := time.Now()
		_, err := output(ctx, cli, []string{"probe", mode}, statusOutputLimit)
		if !errors.Is(err, ErrOutputLimit) {
			t.Fatalf("%s: %v, want ErrOutputLimit", mode, err)
		}
		if time.Since(start) > 10*time.Second || len(err.Error()) > 200 {
			t.Fatalf("%s: slow or long error: %q", mode, err)
		}
	}
}

func TestCLIErrorTextIsBoundedAndRedacted(t *testing.T) {
	cli := fixtureCLI(t)
	ctx := context.Background()
	_, err := output(ctx, cli, []string{"probe", "fail"}, statusOutputLimit)
	var te *Error
	if !errors.As(err, &te) {
		t.Fatalf("error type %T", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "boom <redacted> second line") || strings.Contains(msg, "\n") || strings.Contains(msg, "ghs_") {
		t.Fatalf("stderr not redacted on one line: %q", msg)
	}
	long := &Error{Args: []string{"clone"}, Err: errors.New("exit status 1"), Stderr: strings.Repeat("e", stderrLimit)}
	if len(long.Error()) > 1024 {
		t.Fatalf("error text %d bytes", len(long.Error()))
	}
}

func TestStartedProcessHasOwnProcessGroup(t *testing.T) {
	proc, err := (CLI{Binary: "/bin/sleep"}).startInput(context.Background(), []string{"30"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proc.Kill(); <-proc.Done() }()
	pgid, err := syscall.Getpgid(proc.PID())
	if err != nil {
		t.Fatal(err)
	}
	if pgid != proc.PID() || pgid == syscall.Getpgrp() {
		t.Fatalf("pgid %d, pid %d, ours %d: child shares the daemon's process group", pgid, proc.PID(), syscall.Getpgrp())
	}
}

// A grandchild holding the copied output pipe cannot keep a started process
// looking alive after the process itself exits.
func TestStartedProcessDoneDespiteLingeringGrandchild(t *testing.T) {
	proc, err := fixtureCLI(t).startInput(context.Background(), []string{"run", "linger"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-proc.Done():
	case <-time.After(execWaitDelay + 2*time.Second):
		t.Fatal("Done waited on a grandchild's pipe")
	}
}

// A cancelled context refuses to start a long-lived child, and an already
// started one is not bound to its context.
func TestStartedProcessIgnoresLaterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (CLI{Binary: "/bin/sleep"}).startInput(ctx, []string{"30"}, nil, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("start with cancelled context: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	proc, err := (CLI{Binary: "/bin/sleep"}).startInput(ctx, []string{"30"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proc.Kill(); <-proc.Done() }()
	cancel()
	select {
	case <-proc.Done():
		t.Fatal("cancelling the start context stopped the child")
	case <-time.After(500 * time.Millisecond):
	}
}
