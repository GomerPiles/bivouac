package manager

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/github"
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
	failures    map[string]error
}

func (p retainedValidationProvider) ValidateRetained(name string) error {
	(*p.validations)++
	if p.failures != nil {
		return p.failures[name]
	}
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
	if err := h.m.Reconcile(context.Background()); err != nil || validations != 1 {
		t.Fatal("retained OS validation skipped", err)
	}
	for _, call := range h.fp.CallLog() {
		if strings.Contains(call, "bivouac-macos-retained") {
			t.Fatal("unprovable record received provider operation", call)
		}
	}
	inst, ok := h.store.Get("retained")
	if !ok || inst.Phase != state.PhaseListening || !strings.Contains(inst.LastError, "retained guest validation") {
		t.Fatal("record was not retained and reported")
	}
	if h.m.activeCount() != 0 {
		t.Fatal("invalid record was tracked")
	}
}

func TestRetainedValidationKeepsOneRecordAndReconcilesOthers(t *testing.T) {
	h := newHarness(t, nil)
	linux := fake.New("linux", "ctl-test")
	pc := h.m.o.Config.Providers["macos"]
	vzConfig := *pc.VZ
	vzConfig.GuestOS = "linux"
	pc.VZ = &vzConfig
	h.m.o.Config.Providers["linux"] = pc
	validations := 0
	bad := "bivouac-linux-corrupt"
	h.m.o.Providers["linux"] = retainedValidationProvider{Provider: linux, validations: &validations, failures: map[string]error{bad: errors.New("retained guest manifest unavailable")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); h.m.Wait() }()
	for _, entry := range []struct {
		id, provider, name string
		p                  *fake.Provider
	}{{"corrupt", "linux", bad, linux}, {"healthy", "linux", "bivouac-linux-healthy", linux}, {"dead", "macos", "bivouac-macos-dead", h.fp}} {
		inst := &state.Instance{ID: entry.id, Provider: entry.provider, Name: entry.name, Phase: state.PhaseListening, ScaleSetID: 100, CreatedAt: time.Now()}
		if entry.id == "corrupt" {
			inst.RunnerID = 99
		}
		if err := h.store.Put(inst); err != nil {
			t.Fatal(err)
		}
		if entry.id == "dead" {
			continue
		}
		if err := entry.p.Create(ctx, provider.Spec{Name: entry.name, Meta: provider.Metadata{ControllerID: h.store.ControllerID(), InstanceID: entry.id}}); err != nil {
			t.Fatal(err)
		}
		if err := entry.p.Start(ctx, entry.name, discard{}); err != nil {
			t.Fatal(err)
		}
		if err := entry.p.StartRunner(ctx, entry.name, []byte("synthetic-jit")); err != nil {
			t.Fatal(err)
		}
	}
	before := len(linux.CallLog())
	if err := h.m.Reconcile(ctx); err != nil {
		t.Fatal("one corrupt record halted reconciliation", err)
	}
	h.eventually("Darwin dead record cleaned", func() bool { _, ok := h.store.Get("dead"); return !ok })
	h.eventually("healthy runner adopted", func() bool { return h.m.activeCount() == 1 })
	inst, ok := h.store.Get("corrupt")
	if !ok || inst.Phase != state.PhaseListening || !strings.Contains(inst.LastError, "retained guest validation") {
		t.Fatal("unprovable record changed or unreported")
	}
	if _, ok := linux.Get(bad); !ok {
		t.Fatal("unprovable clone deleted")
	}
	for _, call := range linux.CallLog()[before:] {
		if strings.Contains(call, bad) {
			t.Fatal("unprovable clone touched", call)
		}
	}
	if capacity, _ := h.m.rawCapacity(ctx, "macos"); capacity != 0 {
		t.Fatal("unprovable record lost its reservation", capacity)
	}
	h.m.converge(ctx, nil, &poller{name: "linux"}, 100, &github.Statistics{TotalAssignedJobs: 1}, nil)
	for _, id := range h.gh.Removed {
		if id == 99 {
			t.Fatal("unadopted registration was withdrawn as surplus")
		}
	}
	if validations != 2 {
		t.Fatal("per-instance validation was skipped", validations)
	}
}
