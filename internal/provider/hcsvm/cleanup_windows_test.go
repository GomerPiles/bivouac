//go:build windows

package hcsvm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStartupRemovesOnlyLegacyInstanceHostKeys(t *testing.T) {
	dir := t.TempDir()
	keep := []string{"other.hostkey", "ABCDEF13.hostkey", "abcdef12.hostkey.extra", "1234567.hostkey", "123456789.hostkey", "instances.json", "12345678.known_hosts"}
	for _, name := range append(append([]string{}, keep...), "abcdef12.hostkey") {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "12345678.hostkey"), 0700); err != nil {
		t.Fatal(err)
	}
	p, h, tr := fixture(t, true)
	opts := p.opts
	opts.StateDir = dir
	if _, err := New(opts, h, tr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "abcdef12.hostkey")); !os.IsNotExist(err) {
		t.Fatal("stale pin remains")
	}
	for _, name := range append(keep, "12345678.hostkey") {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Fatal("unrelated entry removed", name)
		}
	}
}
