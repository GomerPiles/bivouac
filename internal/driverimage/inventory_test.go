package driverimage

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func noCheck(string) error { return nil }

func TestInventoryFingerprintsContentsAndExcludesRuntimeLogs(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "display.inf_package")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(path, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("driver.dll", "aaaa")
	write("atikmdag_dce.log", "host-private-output")
	first, err := inventory(t.Context(), []string{path}, noCheck)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || len(first[0].Files) != 1 || first[0].Files[0].Path != "driver.dll" {
		t.Fatal("runtime output entered inventory")
	}
	key := imageKey("base", first)
	write("atikmdag_dce.log", "changed host-private-output")
	second, err := inventory(t.Context(), []string{path, path}, noCheck)
	if err != nil || imageKey("base", second) != key {
		t.Fatal("runtime log or duplicate changed key", err)
	}
	write("driver.dll", "bbbb")
	third, err := inventory(t.Context(), []string{path}, noCheck)
	if err != nil || imageKey("base", third) == key {
		t.Fatal("same-size driver replacement was missed", err)
	}
	if imageKey("other-base", third) == imageKey("base", third) {
		t.Fatal("base was not part of key")
	}
}

func TestInventoryRefusesUntrustedAndCancelledInputs(t *testing.T) {
	if _, err := inventory(t.Context(), []string{t.TempDir()}, func(string) error { return errors.New("not protected") }); err == nil {
		t.Fatal("unprotected source admitted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := inventory(ctx, []string{t.TempDir()}, noCheck); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled inventory continued", err)
	}
	if _, err := inventory(t.Context(), nil, noCheck); err == nil {
		t.Fatal("empty inventory admitted")
	}
}

func TestBoundedCopyRejectsGrowthAndShortWrites(t *testing.T) {
	if _, err := copyBounded(t.Context(), io.Discard, strings.NewReader("growing"), 3); err == nil {
		t.Fatal("growing input admitted")
	}
	if n, err := copyBounded(t.Context(), io.Discard, strings.NewReader("exact"), 5); n != 5 || err != nil {
		t.Fatal(n, err)
	}
	if _, err := copyBounded(t.Context(), shortWriter{}, strings.NewReader("exact"), 5); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short write ignored", err)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
