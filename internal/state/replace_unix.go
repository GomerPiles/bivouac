//go:build !windows

package state

import (
	"fmt"
	"os"
	"path/filepath"
)

// replaceFile renames from over to, then syncs the parent directory so the
// new entry survives power loss. Without the directory sync a crash can
// revert the rename and resurrect a record whose guest was already deleted.
func replaceFile(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(to))
	if err != nil {
		return fmt.Errorf("sync %s: %w", filepath.Dir(to), err)
	}
	syncErr := dir.Sync()
	if err := dir.Close(); syncErr == nil {
		syncErr = err
	}
	if syncErr != nil {
		return fmt.Errorf("sync %s: %w", filepath.Dir(to), syncErr)
	}
	return nil
}
