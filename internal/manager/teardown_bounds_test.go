package manager

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

// A guest that never closes its diagnostics stream cannot hold teardown, and
// with it the capacity slot, past the diagnostics deadline.
func TestTeardownBoundsDiagnostics(t *testing.T) {
	h := newHarness(t, nil)
	h.m.o.DiagTimeout = 100 * time.Millisecond
	inst := &state.Instance{ID: "diag", Name: "bivouac-macos-diag", Provider: "macos", ScaleSetID: 100, Phase: state.PhaseListening, CreatedAt: time.Now()}
	if err := h.store.Put(inst); err != nil {
		t.Fatal(err)
	}
	if err := h.fp.Create(context.Background(), provider.Spec{Name: inst.Name, Meta: provider.Metadata{ControllerID: h.store.ControllerID(), InstanceID: inst.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := h.fp.Start(context.Background(), inst.Name, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	h.fp.HangDiagnostics = true
	done := make(chan teardownOutcome, 1)
	go func() { done <- h.m.teardown(context.Background(), inst, "test") }()
	select {
	case out := <-done:
		if out != teardownDone {
			t.Fatalf("outcome %v", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("teardown hung on diagnostics")
	}
	if len(h.fp.Names()) != 0 || len(h.store.List()) != 0 {
		t.Fatal("guest or record kept after bounded diagnostics")
	}
}

// Stop must not wait for a booting guest to become ready, nor register it.
func TestStopInterruptsBootingGuest(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Budget.ReadyTimeout.Duration = time.Minute })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
	h.eventually("guest booting", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	h.setMode(control.ModeStop)
	h.eventually("booting guest torn down", func() bool { return len(h.fp.Names()) == 0 && len(h.store.List()) == 0 && h.m.Phase() == "idle" })
	if n := len(h.gh.JITNames()); n != 0 {
		t.Fatalf("stopped guest registered %d runner(s)", n)
	}
	for _, e := range h.store.Errors() {
		t.Fatalf("stop recorded as a failure: %+v", e)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Off waits for an in-flight guest and joins its goroutine before exiting.
func TestOffWaitsForInFlightGuest(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
	h.eventually("guest booting", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	h.setMode(control.ModeOff)
	select {
	case err := <-done:
		t.Fatal("daemon exited with a guest booting", err)
	case <-time.After(200 * time.Millisecond):
	}
	h.fp.MarkReady(h.instanceNamed("").Name)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not exit after the guest retired")
	}
	if len(h.fp.Names()) != 0 || len(h.store.List()) != 0 || h.m.activeCount() != 0 {
		t.Fatal("daemon exited before teardown finished")
	}
}

// A record whose guest lacks our metadata backs off, records its error once,
// and does not keep off from exiting. The record stays for a later start.
func TestUnownedGuestDoesNotBlockOff(t *testing.T) {
	h := newHarness(t, nil)
	h.m.o.UnownedRetryMax = 40 * time.Millisecond
	inst := &state.Instance{ID: "lost", Name: "bivouac-macos-lost", Provider: "macos", ScaleSetID: 100, Phase: state.PhaseDestroying, CreatedAt: time.Now()}
	if err := h.store.Put(inst); err != nil {
		t.Fatal(err)
	}
	h.fp.AddUnowned(inst.Name)
	if err := h.store.RecordError("other", "a real failure"); err != nil {
		t.Fatal(err)
	}
	h.setMode(control.ModeOff)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := h.run(ctx)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unowned guest kept off from exiting")
	}
	if _, ok := h.store.Get(inst.ID); !ok {
		t.Fatal("record for an unowned guest was dropped")
	}
	if _, ok := h.fp.Get(inst.Name); !ok {
		t.Fatal("unowned guest touched")
	}
	errs := h.store.Errors()
	if len(errs) != 2 || errs[0].Message != "a real failure" {
		t.Fatalf("errors = %+v", errs)
	}
}

// notOwnedStatus models App Sandbox and Crosvm, whose Status reports an
// unprovable guest as ErrNotOwned rather than Exists && !Owned.
type notOwnedStatus struct {
	provider.Provider
	on atomic.Bool
}

func (p *notOwnedStatus) Status(ctx context.Context, name string) (provider.Status, error) {
	if p.on.Load() {
		return provider.Status{}, fmt.Errorf("lookup %s: %w", name, provider.ErrNotOwned)
	}
	return p.Provider.Status(ctx, name)
}

// A teardown whose Status returns ErrNotOwned parks like an unowned guest:
// off exits, and the record and guest stay for a later start.
func TestNotOwnedStatusErrorParksTeardown(t *testing.T) {
	h := newHarness(t, nil)
	h.m.o.UnownedRetryMax = 40 * time.Millisecond
	p := &notOwnedStatus{Provider: h.fp}
	h.m.o.Providers["macos"] = p
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
	h.eventually("guest booting", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	inst := h.instanceNamed("")
	p.on.Store(true)
	h.setMode(control.ModeOff)
	h.fp.MarkReady(inst.Name)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ErrNotOwned from Status kept off from exiting")
	}
	if _, ok := h.store.Get(inst.ID); !ok {
		t.Fatal("record for an unprovable guest was dropped")
	}
	if _, ok := h.fp.Get(inst.Name); !ok {
		t.Fatal("unprovable guest deleted")
	}
	for _, call := range h.fp.CallLog() {
		if strings.HasPrefix(call, "stop ") || strings.HasPrefix(call, "delete ") {
			t.Fatalf("unprovable guest touched: %q", call)
		}
	}
	if out := h.m.teardown(context.Background(), inst, "test"); out != teardownUnowned {
		t.Fatalf("outcome %v", out)
	}
}

func TestReconcileRefusalIsTyped(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.GitHub.Demand = config.DemandJIT })
	if err := h.store.Put(&state.Instance{ID: "old", Name: "bivouac-macos-old", Provider: "macos", ScaleSetID: 100, Phase: state.PhaseListening, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Run(context.Background()); !errors.Is(err, ErrRefused) {
		t.Fatalf("refusal = %v", err)
	}
}

func TestFailureTextIsRedactedAndBounded(t *testing.T) {
	h := newHarness(t, nil)
	inst := &state.Instance{ID: "e", Name: "bivouac-macos-e", Provider: "macos", ScaleSetID: 100, Phase: state.PhaseCreating, CreatedAt: time.Now()}
	if err := h.store.Put(inst); err != nil {
		t.Fatal(err)
	}
	secret := "ghs_" + strings.Repeat("A", 36)
	h.m.fail(inst, errors.New("POST https://api.example/x?sig=abc failed with token "+secret+": "+strings.Repeat("body ", 2000)))
	got, _ := h.store.Get(inst.ID)
	errs := h.store.Errors()
	for _, msg := range []string{got.LastError, errs[len(errs)-1].Message} {
		if strings.Contains(msg, secret) || strings.Contains(msg, "sig=abc") || len(msg) > state.MaxMessage {
			t.Fatalf("unsafe error text (%d bytes): %.120s", len(msg), msg)
		}
	}
}

// slowEngine advertises a per-call bound longer than the manager's default
// and needs part of it, like the App Sandbox broker.
type slowEngine struct {
	provider.Provider
	delay time.Duration
}

func (p slowEngine) Capabilities() provider.Capabilities {
	c := p.Provider.Capabilities()
	c.OperationTimeout = 5 * time.Second
	return c
}

func (p slowEngine) Delete(ctx context.Context, name string) error {
	select {
	case <-time.After(p.delay):
		return p.Provider.Delete(ctx, name)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// A provider's advertised operation bound extends the manager's own.
func TestTeardownUsesProviderOperationTimeout(t *testing.T) {
	h := newHarness(t, nil)
	h.m.o.ProviderTimeout = 50 * time.Millisecond
	h.m.o.Providers["macos"] = slowEngine{Provider: h.fp, delay: 300 * time.Millisecond}
	inst := &state.Instance{ID: "slow", Name: "bivouac-macos-slow", Provider: "macos", ScaleSetID: 100, Phase: state.PhaseListening, CreatedAt: time.Now()}
	if err := h.store.Put(inst); err != nil {
		t.Fatal(err)
	}
	if err := h.fp.Create(context.Background(), provider.Spec{Name: inst.Name, Meta: provider.Metadata{ControllerID: h.store.ControllerID(), InstanceID: inst.ID}}); err != nil {
		t.Fatal(err)
	}
	if out := h.m.teardown(context.Background(), inst, "test"); out != teardownDone {
		t.Fatalf("outcome %v: slow delete abandoned at the manager's default bound", out)
	}
}
