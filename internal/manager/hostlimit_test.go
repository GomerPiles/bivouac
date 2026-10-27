package manager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/fake"
	"github.com/GomerPiles/bivouac/internal/state"
)

// Apple's two-guest limit is per host. Guests of one vz provider, and
// owned guests without a record, use slots every vz provider sees.
func TestVZHostLimitSpansProviders(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Budget.MaxInstances = 4 })
	p := h.m.o.Config.Providers["macos"]
	tc := *p.VZ
	p.VZ = &tc
	p.ScaleSet = "bivouac-studio"
	h.m.o.Config.Providers["studio"] = p
	h.m.o.Providers["studio"] = fake.New("studio", "ctl-test")
	if n, _ := h.m.rawCapacity(context.Background(), "macos"); n != 2 {
		t.Fatalf("empty host capacity = %d", n)
	}
	if err := h.store.Put(&state.Instance{ID: "s1", Provider: "studio", Name: "bivouac-studio-s1", Phase: state.PhaseRunning, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if n, _ := h.m.rawCapacity(context.Background(), "macos"); n != 1 {
		t.Fatalf("another provider's guest ignored: %d", n)
	}
	// An owned running guest with no record (an orphan awaiting reconcile)
	// also occupies a slot.
	if err := h.fp.Create(context.Background(), provider.Spec{Name: "bivouac-studio-orphan", Meta: provider.Metadata{ControllerID: "ctl-test"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.fp.Start(context.Background(), "bivouac-studio-orphan", discard{}); err != nil {
		t.Fatal(err)
	}
	if n, _ := h.m.rawCapacity(context.Background(), "macos"); n != 0 {
		t.Fatalf("orphan ignored: %d", n)
	}
}

type discard struct{}

func (discard) Write(b []byte) (int, error) { return len(b), nil }

// The provider's manifest proof, rather than config, determines exemptions.
type slotProofProvider struct {
	provider.Provider
	exempt map[string]bool
}

func (p slotProofProvider) HostLimitExempt(name string) bool { return p.exempt[name] }

func TestLinuxSlotExemptionRequiresManifestProof(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Budget.MaxInstances = 6 })
	pc := h.m.o.Config.Providers["macos"]
	copyVZ := *pc.VZ
	copyVZ.GuestOS, copyVZ.HostVMLimit, copyVZ.ForeignSlots = "linux", 0, 0
	copyVZ.CPU, copyVZ.MemoryGB = 0, 0
	pc.VZ = &copyVZ
	h.m.o.Config.Providers["linux"] = pc
	name := "bivouac-linux-fixture"
	proof := slotProofProvider{Provider: fake.New("linux", "ctl-test"), exempt: map[string]bool{name: true}}
	h.m.o.Providers["linux"] = proof
	if err := h.store.Put(&state.Instance{ID: "linux", Provider: "linux", Name: name, Phase: state.PhaseRunning, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	inv := &inventory{foreign: []provider.Foreign{{Name: "bivouac-linux-orphan", Running: true, HostLimitExempt: true}}}
	if n, _ := h.m.rawCapacityWith(context.Background(), "macos", inv); n != 2 {
		t.Fatal("proven Linux clones consumed Apple slots", n)
	}
	proof.exempt[name] = false // missing/corrupt clone manifest
	if n, _ := h.m.rawCapacityWith(context.Background(), "macos", inv); n != 1 {
		t.Fatal("unproven record was exempt", n)
	}
	inv.foreign = append(inv.foreign, provider.Foreign{Name: "unknown", Running: true})
	if err := h.store.Put(&state.Instance{ID: "unknown", Name: "unknown", Provider: "removed", Phase: state.PhaseRunning}); err != nil {
		t.Fatal(err)
	}
	if n, _ := h.m.rawCapacityWith(context.Background(), "macos", inv); n != 0 {
		t.Fatal("unknown foreign guest was exempt", n)
	}
}

type retainedValidationProvider struct {
	provider.Provider
	failure     error
	validations *int
}

func (p retainedValidationProvider) ValidateRetained(string) error {
	(*p.validations)++
	return p.failure
}

func TestReconcileChecksRetainedOSBeforeProviderWork(t *testing.T) {
	h := newHarness(t, nil)
	validations := 0
	cause := errors.New("fixture retained guest OS differs")
	p := retainedValidationProvider{Provider: h.fp, failure: cause, validations: &validations}
	h.m.o.Providers["macos"] = p
	if err := h.store.Put(&state.Instance{ID: "retained", Provider: "macos", Name: "bivouac-macos-retained", Phase: state.PhaseListening, ScaleSetID: 100}); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Reconcile(context.Background()); !errors.Is(err, ErrRefused) || !errors.Is(err, cause) || validations != 1 {
		t.Fatal("retained OS validation skipped", err)
	}
	if len(h.fp.CallLog()) != 0 {
		t.Fatal("provider work preceded retained OS validation")
	}
}
