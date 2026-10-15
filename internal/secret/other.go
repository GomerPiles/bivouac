//go:build !darwin && !windows

package secret

import (
	"context"
	"errors"
	"runtime"
)

// Unsupported is the placeholder store on hosts without a credential-store
// implementation yet.
type Unsupported struct{}

var errUnsupported = errors.New("no credential store implemented for " + runtime.GOOS)

// Get implements Store.
func (Unsupported) Get(context.Context, string) ([]byte, error) { return nil, errUnsupported }

// Set implements Store.
func (Unsupported) Set(context.Context, string, []byte) error { return errUnsupported }

// Delete implements Store.
func (Unsupported) Delete(context.Context, string) error { return errUnsupported }

// Default returns the platform store.
func Default() Store { return Unsupported{} }
