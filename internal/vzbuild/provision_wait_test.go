package vzbuild

import (
	"context"
	"errors"
	"testing"

	"github.com/GomerPiles/bivouac/internal/vm"
)

func TestProvisionCaptureRequiresGuestExit(t *testing.T) {
	for _, kind := range []string{"guest", "forced", "error", "cancelled", "cancelled-after-exit"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			stopped := false
			var exitErr error
			switch kind {
			case "guest":
				close(done)
			case "forced":
				exitErr = vm.ErrForcedStop
				close(done)
			case "error":
				exitErr = errors.New("launch failed")
				close(done)
			case "cancelled":
				cancel()
			case "cancelled-after-exit":
				cancel()
				close(done)
			}
			err := requireProvisionExit(ctx, done, func() error { return exitErr }, func() error { stopped = true; return nil })
			if (err == nil) != (kind == "guest") {
				t.Fatal("wrong capture decision", err)
			}
			if exitErr != nil && !errors.Is(err, exitErr) {
				t.Fatal("helper error was lost", err)
			}
			if kind == "cancelled" && (!stopped || !errors.Is(err, context.Canceled)) {
				t.Fatal("cancellation failed to stop helper", err)
			}
		})
	}
}
