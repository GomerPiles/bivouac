package vzbuild

import (
	"context"
	"errors"
	"fmt"
)

// A receipt cannot authorize capture after host power-off or an ambiguous exit.
func requireProvisionExit(ctx context.Context, done <-chan struct{}, exit func() error, stop func() error) error {
	select {
	case <-ctx.Done():
		return errors.Join(ctx.Err(), stop())
	case <-done:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := exit(); err != nil {
			return fmt.Errorf("provisioning VM helper failed (startup or execution): %w", err)
		}
		return nil
	}
}
