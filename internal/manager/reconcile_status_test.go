package manager

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

// statusFaults fails or hangs Status for chosen guests of the fake provider.
type statusFaults struct {
	provider.Provider
	errs map[string]error
	hang map[string]bool
}

func (p statusFaults) Status(ctx context.Context, name string) (provider.Status, error) {
	if p.hang[name] {
		<-ctx.Done()
		return provider.Status{}, ctx.Err()
	}
	if err := p.errs[name]; err != nil {
		return provider.Status{}, err
	}
	return p.Provider.Status(ctx, name)
}

// An unprovable or unreachable record neither aborts startup nor loses its
// record or guest; the remaining records are still reconciled.
func TestReconcileKeepsUnprovableRecords(t *testing.T) {
	h := newHarness(t, nil)
	h.m.o.ProviderTimeout = 100 * time.Millisecond
	h.m.o.Providers["macos"] = statusFaults{
		Provider: h.fp,
		errs:     map[string]error{"bivouac-macos-unowned": provider.ErrNotOwned},
		hang:     map[string]bool{"bivouac-macos-hung": true},
	}
	for _, id := range []string{"unowned", "hung", "dead"} {
		inst := &state.Instance{ID: id, Name: "bivouac-macos-" + id, Provider: "macos", ScaleSetID: 100, Phase: state.PhaseListening, CreatedAt: time.Now()}
		if err := h.store.Put(inst); err != nil {
			t.Fatal(err)
		}
		if id == "dead" {
			continue
		}
		if err := h.fp.Create(context.Background(), provider.Spec{Name: inst.Name, Meta: provider.Metadata{ControllerID: h.store.ControllerID(), InstanceID: id}}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- h.m.Reconcile(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reconcile aborted: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reconcile status call was not bounded")
	}
	h.eventually("dead record reconciled", func() bool { _, ok := h.store.Get("dead"); return !ok })
	h.m.Wait()
	for _, id := range []string{"unowned", "hung"} {
		inst, ok := h.store.Get(id)
		if !ok {
			t.Fatalf("%s: record dropped", id)
		}
		if inst.Phase != state.PhaseListening || !strings.Contains(inst.LastError, "reconcile status") {
			t.Fatalf("%s: phase %s, last error %q", id, inst.Phase, inst.LastError)
		}
		if _, ok := h.fp.Get(inst.Name); !ok {
			t.Fatalf("%s: guest deleted", id)
		}
	}
	for _, call := range h.fp.CallLog() {
		if strings.HasPrefix(call, "stop ") || strings.HasPrefix(call, "delete ") {
			t.Fatalf("unproven guest touched: %q", call)
		}
	}
	if len(h.store.Errors()) < 2 {
		t.Fatalf("errors not recorded: %+v", h.store.Errors())
	}
}
