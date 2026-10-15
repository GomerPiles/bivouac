//go:build !windows

package state

import "os"

// ReadFile reads a control/state file without blocking atomic replacement.
func ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
