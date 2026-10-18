//go:build windows

package crosvm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImageOutputRefusesAliasedInstanceStorage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "instances")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := createJunction(root, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := imageOutputPath(filepath.Join(alias, "Linux-Images"), root); err == nil {
		t.Fatal("junction into disposable storage admitted for publication")
	}
	if _, err := imageOutputPath(filepath.Join(root, "Linux-Images"), alias); err == nil {
		t.Fatal("aliased instance root admitted for publication")
	}
	outside := t.TempDir()
	output, err := imageOutputPath(filepath.Join(outside, "Linux-Images"), root)
	if err != nil || filepath.Base(output) != "Linux-Images" {
		t.Fatal("external image output rejected", err)
	}
	if _, err := imageOutputPath(filepath.Join(outside, "absent", "Linux-Images"), root); err == nil {
		t.Fatal("unresolvable output parent accepted")
	}
}
