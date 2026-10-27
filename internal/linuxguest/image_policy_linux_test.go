//go:build linux

package linuxguest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFactorySanitationDoesNotFollowLinks(t *testing.T) {
	for _, kind := range []string{"directory", "file"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			sentinel := filepath.Join(outside, "Runner_factory.log")
			if err := os.WriteFile(sentinel, []byte("synthetic outside"), 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "directory" {
				if err := os.Symlink(outside, filepath.Join(root, "_diag")); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(filepath.Join(root, "_diag"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(sentinel, filepath.Join(root, "_diag", "Runner_factory.log")); err != nil {
					t.Fatal(err)
				}
			}
			if sanitizeRunnerFactory(root) == nil {
				t.Fatal("linked diagnostics admitted")
			}
			if _, err := os.Stat(sentinel); err != nil {
				t.Fatal("factory sanitation followed a link")
			}
		})
	}
}
