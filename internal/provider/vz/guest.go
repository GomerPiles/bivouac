package vz

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/perf"
)

const guestDirectory = "/tmp/bivouac"
const guestHelper = "/tmp/bivouac-helper"

// RunGuest is the private macOS guest telemetry adapter. The existing shell bootstrap
// still owns job identity and lifecycle. Only the listener wrapper owns sampling.
func RunGuest(ctx context.Context, operation, runner string, out io.Writer) error {
	if runtime.GOOS != "darwin" {
		return errors.New("the guest adapter requires macOS")
	}
	return runGuest(ctx, operation, guestDirectory, runner, out)
}

func runGuest(ctx context.Context, operation, directory, runner string, out io.Writer) error {
	switch operation {
	case "hook":
		// The shell hook already recorded identity; this file is only the
		// recorder's numeric telemetry start marker.
		if err := os.WriteFile(filepath.Join(directory, "job.json"), []byte("{}\n"), 0o600); err != nil {
			return err
		}
		perf.PrintStart(out, runner)
		return nil
	case "hook-completed":
		perf.PrintEnd(ctx, out, directory)
		cache.PrintGuestSummary(ctx, out, directory)
		return nil
	case "run":
		pidFile, err := os.OpenFile(filepath.Join(directory, "listener.pid"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return errors.New("prepare guest listener identity")
		}
		defer func() { _ = pidFile.Close() }()
		listener := exec.CommandContext(ctx, filepath.Join(runner, "bin", "Runner.Listener"), "run")
		listener.Dir = runner
		listener.Stdout, listener.Stderr = out, out
		listener.Cancel = func() error { return listener.Process.Signal(syscall.SIGTERM) }
		listener.WaitDelay = 30 * time.Second
		if err := listener.Start(); err != nil {
			return err
		}
		if _, err := pidFile.WriteString(strconv.Itoa(listener.Process.Pid)); err != nil {
			_ = listener.Process.Kill()
			_ = listener.Wait()
			return errors.New("record guest listener identity")
		}
		stop := perf.StartRecorder(ctx, directory, runner)
		defer stop()
		return listener.Wait()
	default:
		return errors.New("unknown fixed guest operation")
	}
}
