//go:build windows

package winhost

import (
	"os"
	"path/filepath"
	"testing"
)

// A per-user temporary directory is owned by, and writable by, the ordinary
// user the broker options must constrain.
func TestCheckProtectedRejectsUserWritableConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker-options.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckProtected(path); err == nil {
		t.Fatal("user-writable broker configuration accepted")
	}
	if err := CheckProtected("broker-options.json"); err == nil {
		t.Fatal("relative protected path accepted")
	}
}
