package manager

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

func jitConfig(c *config.Config) {
	c.GitHub.Demand = config.DemandJIT
	c.Budget.MaxInstances = 1
	c.Budget.IdleTimeout.Duration = time.Hour
	p := c.Providers["macos"]
	p.IdlePool = 1
	c.Providers["macos"] = p
}

func TestJITPoolOneJobAndDrain(t *testing.T) {
	h := newHarness(t, jitConfig)
	// REST mode must not depend on a scale-set client or open a session.
	h.m.o.GitHub = nil
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.eventually("warm guest", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	first := h.instanceNamed(state.PhaseBooting)
	h.fp.MarkReady(first.Name)
	h.eventually("idle runner", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
	h.fp.SetRunnerJob(first.Name, provider.RunnerJob{RunID: 123, Repository: "example-org/repo", Name: "macos"})
	h.eventually("job identity", func() bool {
		i, _ := h.store.Get(first.ID)
		return i != nil && i.Job != nil && i.Job.RunID == 123 && i.Phase == state.PhaseRunning
	})
	h.setMode(control.ModeDrain)
	time.Sleep(80 * time.Millisecond)
	if !h.gh.Registered(first.Name) || len(h.fp.Names()) != 1 {
		t.Fatal("drain interrupted active job")
	}
	h.fp.ExitRunner(first.Name, 0)
	h.eventually("drained", func() bool { return len(h.store.List()) == 0 })
	h.setMode(control.ModeOn)
	h.eventually("fresh replacement", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	second := h.instanceNamed(state.PhaseBooting)
	if second.Name == first.Name {
		t.Fatal("reused guest")
	}
	h.fp.MarkReady(second.Name)
	h.eventually("second listening", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
	h.gh.SetRemoveError(errors.New("runner busy"))
	h.setMode(control.ModeDrain)
	time.Sleep(80 * time.Millisecond)
	if len(h.fp.Names()) != 1 {
		t.Fatal("stopped runner before successful withdrawal")
	}
	h.gh.SetRemoveError(nil)
	h.eventually("idle withdrawal", func() bool { return len(h.store.List()) == 0 && !h.gh.Registered(second.Name) })
	h.setMode(control.ModeOff)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type ambiguousJIT struct{ *github.Fake }

func (f ambiguousJIT) GenerateRunnerJIT(ctx context.Context, name, group string, labels []string, work string) (github.JITConfig, error) {
	_, _ = f.Fake.GenerateRunnerJIT(ctx, name, group, labels, work)
	return github.JITConfig{}, errors.New("response lost after registration")
}

func TestJITAmbiguousRegistrationCleanup(t *testing.T) {
	h := newHarness(t, jitConfig)
	h.m.o.JIT = ambiguousJIT{h.gh}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.eventually("boot", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	inst := h.instanceNamed(state.PhaseBooting)
	h.fp.MarkReady(inst.Name)
	h.eventually("failed request cleaned by name", func() bool { _, ok := h.store.Get(inst.ID); return !ok && !h.gh.Registered(inst.Name) })
	time.Sleep(80 * time.Millisecond)
	if len(h.fp.Names()) != 0 {
		t.Fatal("failed pool registration retried without backoff")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestJITRestartPreservesIdleRegistration(t *testing.T) {
	h := newHarness(t, jitConfig)
	ctx, cancel := context.WithCancel(context.Background())
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.eventually("boot", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	inst := h.instanceNamed(state.PhaseBooting)
	h.fp.MarkReady(inst.Name)
	h.eventually("idle", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Simulate a crash between connection and persisting listening.
	_, err := h.store.Update(inst.ID, func(i *state.Instance) { i.Phase = state.PhaseReady })
	if err != nil {
		t.Fatal(err)
	}
	h.m, err = New(h.m.o)
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done = h.run(ctx2)
	h.eventually("adopted listening state", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
	time.Sleep(80 * time.Millisecond)
	if !h.gh.Registered(inst.Name) || len(h.fp.Names()) != 1 {
		t.Fatal("restart withdrew an idle runner despite on mode")
	}
	h.fp.SetRunnerJob(inst.Name, provider.RunnerJob{RunID: 456, Repository: "example-org/repo", Name: "macos"})
	h.eventually("adopted job", func() bool {
		i, _ := h.store.Get(inst.ID)
		return i != nil && i.Phase == state.PhaseRunning && i.Job != nil
	})
	h.setMode(control.ModeStop)
	h.eventually("stop cleanup", func() bool { return len(h.store.List()) == 0 && !h.gh.Registered(inst.Name) })
	h.setMode(control.ModeOff)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestJITDrainBeforeReadySkipsRegistration(t *testing.T) {
	h := newHarness(t, jitConfig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.eventually("boot", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	inst := h.instanceNamed(state.PhaseBooting)
	h.setMode(control.ModeDrain)
	h.eventually("drain mode", func() bool { return h.m.Phase() == "draining" })
	h.fp.MarkReady(inst.Name)
	h.eventually("provisioning guest withdrawn", func() bool { return len(h.store.List()) == 0 })
	for _, call := range h.fp.CallLog() {
		if strings.Contains(call, "start-runner") {
			t.Fatalf("started paused runner: %s", call)
		}
	}
	h.setMode(control.ModeOff)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type delayedStop struct {
	provider.Provider
	started chan struct{}
	release chan struct{}
}

func (p delayedStop) StopRunner(ctx context.Context, name string) error {
	close(p.started)
	select {
	case <-p.release:
		return p.Provider.StopRunner(ctx, name)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestStopAllowsWorkerEscalationBeforeGuestDeletion(t *testing.T) {
	h := newHarness(t, jitConfig)
	delayed := delayedStop{Provider: h.fp, started: make(chan struct{}), release: make(chan struct{})}
	h.m.o.Providers["macos"] = delayed
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.eventually("boot", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	inst := h.instanceNamed(state.PhaseBooting)
	h.fp.MarkReady(inst.Name)
	h.eventually("idle", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
	h.fp.SetRunnerJob(inst.Name, provider.RunnerJob{RunID: 789, Repository: "example-org/repo", Name: "macos"})
	h.eventually("job", func() bool { return h.instanceNamed(state.PhaseRunning) != nil })
	h.setMode(control.ModeStop)
	select {
	case <-delayed.started:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not reach runner")
	}
	// Model a step consuming the worker's full 7.5 + 2.5 second signal
	// escalation. The guest must still exist while its result is reported.
	time.Sleep(11 * time.Second)
	if st, err := h.fp.Status(context.Background(), inst.Name); err != nil || !st.Running {
		close(delayed.release)
		t.Fatal("guest deleted before worker could report cancellation")
	}
	close(delayed.release)
	h.eventually("cleanup", func() bool { return len(h.store.List()) == 0 && !h.gh.Registered(inst.Name) })
	h.setMode(control.ModeOff)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
