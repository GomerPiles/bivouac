//go:build windows

package main

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

func TestHCSReadinessUsesDaemonLogger(t *testing.T) {
	store, err := state.Open(t.TempDir(), func() string { return "test-controller" })
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	cfg := &config.Config{Providers: map[string]config.Provider{
		"windows": {Type: "hcs", HCS: &config.HCS{Image: "windows", GuestName: "bivouac-image", GuestUser: "ciuser", CPU: 4, MemoryGB: 8, RunnerDir: `C:\actions-runner`}},
	}}
	providers, err := buildProviders(t.Context(), cfg, store, t.TempDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	defer closeProviders(providers)
	// Prefix rejection happens before any VM host or guest contact.
	err = providers["windows"].WaitReady(t.Context(), "foreign-name")
	if !errors.Is(err, provider.ErrNotOwned) || !bytes.Contains(buf.Bytes(), []byte(`"msg":"hcs readiness timings"`)) {
		t.Fatal("readiness observation did not reach daemon sink")
	}
}
