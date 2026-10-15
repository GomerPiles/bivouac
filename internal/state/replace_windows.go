//go:build windows

package state

import (
	"os"
	"path/filepath"
)

// Root.Rename uses Windows POSIX replacement semantics where supported.
// Readers opened with delete sharing can keep the old file while a new
// snapshot replaces its directory entry. Never remove the destination first:
// a failed replacement must preserve the durable ownership record.
func replaceFile(from, to string) error {
	root, err := os.OpenRoot(filepath.Dir(to))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return root.Rename(filepath.Base(from), filepath.Base(to))
}
