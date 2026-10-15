//go:build windows

package crosvm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/redact"
	"golang.org/x/sys/windows"
)

// RunSupervisor holds the kill-on-close native job independently of the main
// manager. Its crash kills every VM child; manager crashes leave it running.
// Only a previously journalled immutable envelope is accepted.
func RunSupervisor(ctx context.Context, path string) error {
	envelope, err := loadEnvelope(path)
	if err != nil {
		return err
	}
	o, r := envelope.Options, envelope.Record
	lock, err := (control.Files{Dir: r.Directory}).Acquire()
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()
	if _, err := os.Stat(filepath.Join(r.Directory, "native.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("native supervisor launch is single-use")
	}
	// Stop may already have abandoned this launch; then journal nothing.
	if _, err := os.Stat(filepath.Join(r.Directory, "stop")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("native launch was abandoned before supervision")
	}
	supervisor, live, err := Identity(windows.GetCurrentProcessId())
	if err != nil || !live {
		return errors.New("supervisor identity unavailable")
	}
	state := NativeState{Supervisor: supervisor, Phase: "starting"}
	if err := writeJSON(r.Directory, "native.json", state); err != nil {
		return err
	}
	attempted := false
	defer func() {
		if !attempted {
			state.Phase = "failed"
			state.Empty = true
			_ = writeJSON(r.Directory, "native.json", state)
		}
	}()
	if err := verifyInventory(r); err != nil {
		return err
	}
	if err := verifyLaunchInputs(o); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(r.Directory, "stop")); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(filepath.Join(r.Directory, "native.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	redacted := redact.NewWriter(file)
	defer func() { _ = redacted.Close() }()
	// Both native streams share one serialized sink. The cap precedes the
	// redactor, bounding its partial-line buffer as well as the file.
	sink := &cappedWriter{w: redacted, limit: logLimit}
	attempted = true
	child, err := startNative(o, r, sink, sink, func() error {
		state.JobOwned = true
		return writeJSON(r.Directory, "native.json", state)
	})
	if err != nil {
		state.Phase = "failed"
		state.Empty = !state.JobOwned
		return errors.Join(err, writeJSON(r.Directory, "native.json", state))
	}
	defer func() { _ = child.Close() }()
	state.VM = child.identity
	state.Phase = "running"
	if err := writeJSON(r.Directory, "native.json", state); err != nil {
		_ = child.Stop()
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		alive, err := child.Alive()
		if err != nil {
			_ = child.Stop()
			return err
		}
		if !alive {
			break
		}
		stop := false
		if _, err := os.Stat(filepath.Join(r.Directory, "stop")); err == nil {
			stop = true
		} else if !errors.Is(err, os.ErrNotExist) {
			stop = true
		}
		if err := verifyInventory(r); err != nil {
			stop = true
		}
		if logLimitReached(r.Directory, sink) {
			stop = true
		}
		if stop {
			if err := child.Stop(); err != nil {
				return err
			}
			break
		}
		select {
		case <-ctx.Done():
			_ = child.Stop()
			stop = true
		case <-ticker.C:
		}
		if stop {
			break
		}
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := child.WaitEmpty(stopCtx); err != nil {
		return err
	}
	if err := windows.GetExitCodeProcess(child.process, &state.ExitCode); err != nil {
		return err
	}
	state.Phase = "exited"
	state.Empty = true
	for _, done := range child.pumps {
		select {
		case err := <-done:
			if err != nil {
				return err
			}
		case <-stopCtx.Done():
			return stopCtx.Err()
		}
	}
	if err := redacted.Close(); err != nil {
		return err
	}
	return writeJSON(r.Directory, "native.json", state)
}
