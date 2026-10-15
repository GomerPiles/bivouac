package manager

import (
	"context"
	"testing"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/state"
)

func TestPollCapacityIncludesActiveAndPausedRunners(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Budget.MaxInstances = 1 })
	ctx := context.Background()
	h.m.accepting.Store(true)
	if got := h.m.pollCapacity(ctx, "macos"); got != 1 {
		t.Fatalf("idle poll capacity = %d, want 1", got)
	}
	if err := h.store.Put(&state.Instance{ID: "active", Name: "bivouac-macos-active", Provider: "macos", Phase: state.PhaseRunning}); err != nil {
		t.Fatal(err)
	}
	if free, _ := h.m.capacity(ctx, "macos"); free != 0 {
		t.Fatalf("busy local capacity = %d, want 0", free)
	}
	if got := h.m.pollCapacity(ctx, "macos"); got != 1 {
		t.Fatalf("busy poll capacity = %d, want 1", got)
	}
	h.m.accepting.Store(false)
	if got := h.m.pollCapacity(ctx, "macos"); got != 1 {
		t.Fatalf("paused poll capacity = %d, want 1", got)
	}
	if err := h.store.Remove("active"); err != nil {
		t.Fatal(err)
	}
	if free, _ := h.m.capacity(ctx, "macos"); free != 0 {
		t.Fatalf("paused local capacity = %d, want 0", free)
	}
	if got := h.m.pollCapacity(ctx, "macos"); got != 1 {
		t.Fatalf("paused idle poll capacity = %d, want 1", got)
	}
}

func TestPollCapacityRespectsForeignSlots(t *testing.T) {
	h := newHarness(t, nil)
	h.fp.AddForeign("foreign")
	if got := h.m.pollCapacity(context.Background(), "macos"); got != 1 {
		t.Fatalf("poll capacity with foreign guest = %d, want 1", got)
	}
}
