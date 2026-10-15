package crosvm

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func launchInputFixture(t *testing.T) Options {
	t.Helper()
	o, _ := fixture(t)
	if err := os.MkdirAll(filepath.Dir(o.Binary), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("pinned small launch input")
	hash := sha256.Sum256(data)
	o.BinarySHA256 = hex.EncodeToString(hash[:])
	o.KernelSHA256, o.InitrdSHA256 = o.BinarySHA256, o.BinarySHA256
	for _, path := range []string{o.Binary, o.Kernel, o.Initrd, o.Baseline} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

func TestLaunchUsesMetadataAndSetupChecksToolPins(t *testing.T) {
	o := launchInputFixture(t)
	if err := verifyLaunchInputs(o); err != nil {
		t.Fatal(err)
	}
	if err := verifySetupInputs(o); err != nil {
		t.Fatal(err)
	}
	// Images are operator-managed: contents are deliberately not fingerprinted.
	if err := os.WriteFile(o.Baseline, []byte("different image contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyLaunchInputs(o); err != nil {
		t.Fatal("baseline contents were hashed", err)
	}
	for _, path := range []string{o.Binary, o.Kernel, o.Initrd} {
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("changed tool"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := verifyLaunchInputs(o); err != nil {
			t.Fatal("static tool was rehashed at launch", err)
		}
		if verifySetupInputs(o) == nil {
			t.Fatal("changed setup tool accepted", path)
		}
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{t.TempDir(), filepath.Join(t.TempDir(), "missing")} {
		o.Baseline = path
		if verifyLaunchInputs(o) == nil {
			t.Fatal("invalid baseline metadata accepted")
		}
	}
	o.Baseline = filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(o.Baseline, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if verifyLaunchInputs(o) == nil {
		t.Fatal("empty baseline accepted")
	}
}
