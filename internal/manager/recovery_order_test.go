package manager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

type inventoryBeforeRecovery struct {
	provider.Provider
	manager *Manager
}

func (p inventoryBeforeRecovery) List(ctx context.Context) ([]provider.Owned, []provider.Foreign, error) {
	p.manager.mu.Lock()
	started := len(p.manager.runs) != 0
	p.manager.mu.Unlock()
	if started {
		return nil, nil, errors.New("recovery started before inventory finished")
	}
	return p.Provider.List(ctx)
}

func TestReconcileInventoriesBeforeStartingDeadGuestRecovery(t *testing.T) {
	h := newHarness(t, jitConfig)
	h.m.o.Providers["macos"] = inventoryBeforeRecovery{Provider: h.fp, manager: h.m}
	inst := &state.Instance{ID: "dead", Provider: "macos", Name: "bivouac-macos-dead", Phase: state.PhaseListening, CreatedAt: time.Now().Add(-time.Hour)}
	if err := h.store.Put(inst); err != nil {
		t.Fatal(err)
	}
	if err := h.fp.Create(context.Background(), provider.Spec{Name: inst.Name, Meta: provider.Metadata{ControllerID: h.store.ControllerID(), InstanceID: inst.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.eventually("dead guest disposed and record removed", func() bool { return len(h.store.List()) == 0 && len(h.fp.Names()) == 0 })
}
