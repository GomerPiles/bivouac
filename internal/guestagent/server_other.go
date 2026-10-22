//go:build !darwin && !linux && !windows

package guestagent

import (
	"context"
	"errors"
	"io"
)

// RunAgent is unavailable outside macOS and Linux guests.
func RunAgent(context.Context) error {
	return errors.New("the guest agent runs in macOS and Linux guests")
}

func RunCLI(ctx context.Context, _ []string, _ io.Reader) error { return RunAgent(ctx) }
