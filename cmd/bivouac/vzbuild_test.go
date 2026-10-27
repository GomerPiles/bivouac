//go:build darwin

package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/paths"
)

func TestBuildBaselineExplicitHelperDispatchBeforeConfig(t *testing.T) {
	dir := t.TempDir()
	e := env{layout: paths.Layout{Config: filepath.Join(dir, "missing-config")}}
	// Unknown recipe fails before any build I/O. A config load would produce a
	// missing-config error instead, so this test cannot accidentally launch a VM.
	err := e.vzCmd(context.Background(), []string{"build-baseline", "--helper", "./helper", "--recipe", "unknown"})
	if err == nil || err.Error() != "unknown Linux VZ baseline recipe" {
		t.Fatal("explicit helper attempted config load", err)
	}
	if err := e.vzCmd(context.Background(), []string{"build-baseline", "--provider", "linux", "--helper", "./helper"}); err == nil || !strings.Contains(err.Error(), "choose --provider or --helper") {
		t.Fatal("ambiguous helper source accepted", err)
	}
	if err := e.vzCmd(context.Background(), []string{"build-baseline", "--bad-flag"}); !errors.Is(err, errUsage) {
		t.Fatal("unknown flag accepted", err)
	}
}
