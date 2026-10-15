//go:build !darwin && !linux

package guestagent

import (
	"context"
	"errors"
)

// RunAgent is unavailable outside macOS and Linux guests.
func RunAgent(context.Context) error {
	return errors.New("the guest agent runs in macOS and Linux guests")
}
