//go:build windows

package appsandbox

import (
	"os"
	"path/filepath"
	"testing"
)

// A per-user temporary directory is owned by, and writable by, the ordinary
// user the broker options must constrain.
func TestCheckProtectedFileRejectsUserWritableConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker-options.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckProtectedFile(path); err == nil {
		t.Fatal("user-writable broker configuration accepted")
	}
	if err := CheckProtectedFile("broker-options.json"); err == nil {
		t.Fatal("relative protected path accepted")
	}
}
