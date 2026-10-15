//go:build !darwin && !windows

// Package install registers bivouac with the host's service manager.
package install

import (
	"context"
	"errors"
	"runtime"
)

// Paths are the files install touches.
type Paths struct {
	Binary string
	LogDir string
}

var errUnsupported = errors.New("install is not implemented for " + runtime.GOOS + " yet (Windows: service or scheduled task)")

// Install is not available on this platform yet.
func Install(context.Context, Paths) (string, error) { return "", errUnsupported }

// Uninstall is not available on this platform yet.
func Uninstall(context.Context) error { return errUnsupported }

// Kickstart is not available on this platform yet.
func Kickstart(context.Context) error { return errUnsupported }

// Installed reports false on this platform.
func Installed(context.Context) (string, bool, error) { return "", false, nil }
