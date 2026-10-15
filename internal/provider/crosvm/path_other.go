//go:build !windows

package crosvm

import "path/filepath"

// resolvePath returns the path of an existing file with symlinks resolved.
func resolvePath(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}
