//go:build windows

package winhost

import (
	"os"
	"path/filepath"
	"testing"
)

// A per-user temporary directory is owned by, and writable by, the ordinary
// user the VM host configuration must constrain.
func TestCheckProtectedRejectsUserWritableConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vmhost.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckProtected(path); err == nil {
		t.Fatal("user-writable VM host configuration accepted")
	}
	if err := CheckProtected("vmhost.json"); err == nil {
		t.Fatal("relative protected path accepted")
	}
}
