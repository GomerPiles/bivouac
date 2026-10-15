package manager

import (
	"context"
	"testing"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/state"
)

func TestContainerPairCapacityAndFrozenReservation(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Budget.ReserveCPU = 2
		p := c.Providers["macos"]
		p.Tart.CPU = 4
		p.Tart.MemoryGB = 8
		p.Tart.Containers = &config.Containers{Engine: "docker", Baseline: "ci-linux-engine", CPU: 2, MemoryGB: 4, Helper: "/opt/bivouac/linux-arm64"}
		c.Providers["macos"] = p
	})
	if n, _ := h.m.rawCapacity(context.Background(), "macos"); n != 1 {
		t.Fatalf("pair CPU admission = %d", n)
	}
	i := &state.Instance{ID: "pair", Provider: "macos", Name: "bivouac-macos-pair", EngineName: "bivouac-macos-pair-engine", ContainerEngine: "docker", CPU: 6, MemoryGB: 12, Phase: state.PhaseRunning}
	if err := h.store.Put(i); err != nil {
		t.Fatal(err)
	}
	// Smaller config for future jobs must not erase a live pair's reservation.
	p := h.m.o.Config.Providers["macos"]
	p.Tart.CPU = 1
	p.Tart.Containers.CPU = 2
	h.m.o.Config.Providers["macos"] = p
	if n, _ := h.m.rawCapacity(context.Background(), "macos"); n != 0 {
		t.Fatalf("live pair reservation was recomputed: %d", n)
	}
	_, err := h.store.Update(i.ID, func(i *state.Instance) { i.Phase = state.PhaseDeregistering })
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := h.m.rawCapacity(context.Background(), "macos"); n != 2 {
		t.Fatalf("confirmed pair deletion did not release resources: %d", n)
	}
}

func TestRetainedPairRejectsTopologyChanges(t *testing.T) {
	h := newHarness(t, nil)
	i := &state.Instance{ID: "pair", Provider: "macos", Name: "bivouac-macos-pair", EngineName: "bivouac-macos-pair-engine", ContainerEngine: "docker", Phase: state.PhaseDestroying, ScaleSetID: 1}
	if err := h.store.Put(i); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Reconcile(context.Background()); err == nil {
		t.Fatal("disabled container topology accepted with retained pair")
	}
	p := h.m.o.Config.Providers["macos"]
	p.Tart.Containers = &config.Containers{Engine: "podman"}
	h.m.o.Config.Providers["macos"] = p
	if err := h.m.Reconcile(context.Background()); err == nil {
		t.Fatal("changed container engine accepted with retained pair")
	}
	if calls := h.fp.CallLog(); len(calls) != 0 {
		t.Fatalf("topology check touched guest: %v", calls)
	}
}
