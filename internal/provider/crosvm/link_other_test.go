//go:build !windows

package crosvm

import "os"

// linkDirectory makes link name the existing directory target.
func linkDirectory(target, link string) error { return os.Symlink(target, link) }
