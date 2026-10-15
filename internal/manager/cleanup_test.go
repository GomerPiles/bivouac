package manager

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

func TestGuestLossReleasesCapacityWhileBusyCleanupSurvivesRestart(t *testing.T) {
	for _, demand := range []config.Demand{config.DemandScaleSet, config.DemandJIT} {
		t.Run(string(demand), func(t *testing.T) {
			h := newHarness(t, func(c *config.Config) {
				if demand == config.DemandJIT {
					jitConfig(c)
				}
				c.Budget.MaxInstances = 1
				c.Budget.IdleTimeout.Duration = time.Hour
				p := c.Providers["macos"]
				p.MaxInstances = 1
				p.Tart.CPU, p.Tart.MemoryGB, p.Tart.ForeignSlots = 6, 8, 1
				c.Providers["macos"] = p
			})
			ctx, cancel := context.WithCancel(context.Background())
			h.setMode(control.ModeOn)
			done := h.run(ctx)
			if demand == config.DemandScaleSet {
				h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
			}
			h.eventually("first boot", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
			first := h.instanceNamed(state.PhaseBooting)
			h.fp.MarkReady(first.Name)
			h.eventually("first listening", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
			first, _ = h.store.Get(first.ID)
			h.gh.SetRunnerRemoveError(first.RunnerID, errors.New("runner still busy"))
			h.fp.SetRunnerJob(first.Name, provider.RunnerJob{RunID: 1, Repository: "example-org/repo", Name: "lost"})
			h.eventually("first running", func() bool { return h.instanceNamed(state.PhaseRunning) != nil })
			if demand == config.DemandScaleSet {
				h.gh.SetStatistics(github.Statistics{TotalAssignedJobs: 1, TotalRunningJobs: 1})
			}
			h.fp.Kill(first.Name)
			h.eventually("deletion proof persisted", func() bool {
				i, ok := h.store.Get(first.ID)
				return ok && i.Phase == state.PhaseDeregistering && !i.GuestDeletedAt.IsZero()
			})
			if demand == config.DemandScaleSet {
				if cap := h.m.pollCapacity(ctx, "macos"); cap != 2 {
					t.Fatalf("remote ceiling must include busy registration: %d", cap)
				}
				// The old assigned job must not itself trigger a replacement.
				time.Sleep(80 * time.Millisecond)
				if len(h.fp.Names()) != 0 {
					t.Fatal("provisioned for the lost job's stale statistics")
				}
			}
			cancel()
			<-done
			// Reopen the durable file and make a new controller, not just a new loop.
			var err error
			h.store, err = state.Open(h.dir, func() string { return "unused" })
			if err != nil {
				t.Fatal(err)
			}
			h.m.o.Store = h.store
			h.m, err = New(h.m.o)
			if err != nil {
				t.Fatal(err)
			}
			ctx2, cancel2 := context.WithCancel(context.Background())
			defer cancel2()
			done = h.run(ctx2)
			if demand == config.DemandScaleSet {
				h.gh.Push(&github.Message{MessageID: 2, Statistics: &github.Statistics{TotalAssignedJobs: 2, TotalRunningJobs: 1}})
			}
			h.eventually("replacement boot while old registration busy", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
			second := h.instanceNamed(state.PhaseBooting)
			if second.Name == first.Name || len(h.fp.Names()) != 1 {
				t.Fatal("fresh guest budget exceeded")
			}
			h.fp.MarkReady(second.Name)
			h.eventually("replacement listening", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
			h.eventually("status separates pending registration", func() bool {
				s, _ := h.files.ReadStatus()
				return s != nil && s.Budgets.Active == 1 && len(s.Guests) == 1 && len(s.PendingCleanup) == 1 && strings.Contains(Describe(s, control.ModeOn, true), "VM deleted")
			})
			h.fp.SetRunnerJob(second.Name, provider.RunnerJob{RunID: 2, Repository: "example-org/repo", Name: "replacement"})
			h.eventually("replacement running", func() bool { return h.instanceNamed(state.PhaseRunning) != nil })
			h.setMode(control.ModeDrain)
			h.fp.ExitRunner(second.Name, 0)
			h.eventually("replacement cleaned independently", func() bool { _, ok := h.store.Get(second.ID); return !ok && h.gh.Registered(first.Name) })
			h.gh.SetRunnerRemoveError(first.RunnerID, nil)
			h.eventually("backlog cleared unattended", func() bool { return len(h.store.List()) == 0 && !h.gh.Registered(first.Name) })
			cancel2()
			<-done
		})
	}
}

func TestRepeatedGuestLossBoundsCleanupBacklog(t *testing.T) {
	h := newHarness(t, jitConfig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.SetRemoveError(errors.New("GitHub unavailable"))
	for range 2 {
		h.eventually("boot", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
		inst := h.instanceNamed(state.PhaseBooting)
		h.fp.MarkReady(inst.Name)
		h.eventually("listening", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
		h.fp.Kill(inst.Name)
		h.eventually("lost guest pending cleanup", func() bool { i, ok := h.store.Get(inst.ID); return ok && i.Phase == state.PhaseDeregistering })
	}
	time.Sleep(100 * time.Millisecond)
	if len(h.store.List()) != 2 || len(h.fp.Names()) != 0 {
		t.Fatal("cleanup circuit did not halt provisioning")
	}
	if cap, _ := h.m.capacity(ctx, "macos"); cap != 0 {
		t.Fatalf("backlog capacity %d", cap)
	}
	h.gh.SetRemoveError(nil)
	h.eventually("pool resumes after cleanup succeeds", func() bool { return len(h.store.List()) == 1 && h.instanceNamed(state.PhaseBooting) != nil })
	// Stop interrupts the booting guest; it never needs to become ready.
	h.setMode(control.ModeStop)
	h.eventually("clean", func() bool { return len(h.store.List()) == 0 && len(h.fp.Names()) == 0 })
	cancel()
	<-done
}

type uncertainDeletion struct {
	provider.Provider
	statusErr bool
	deleteErr bool
	noDelete  bool
}

func (p uncertainDeletion) Status(ctx context.Context, name string) (provider.Status, error) {
	if p.statusErr {
		return provider.Status{}, errors.New("engine unavailable")
	}
	return p.Provider.Status(ctx, name)
}
func (p uncertainDeletion) Delete(ctx context.Context, name string) error {
	if p.deleteErr {
		return errors.New("delete failed")
	}
	if p.noDelete {
		return nil
	}
	return p.Provider.Delete(ctx, name)
}

func TestCleanupCannotReleaseUnconfirmedGuestReservation(t *testing.T) {
	for _, kind := range []string{"status error", "delete error", "delete did nothing", "unowned"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t, func(c *config.Config) { c.Budget.MaxInstances = 1 })
			inst := &state.Instance{ID: "lost", Name: "bivouac-macos-lost", Provider: "macos", ScaleSetID: 100, Phase: state.PhaseDestroying, CreatedAt: time.Now()}
			if err := h.store.Put(inst); err != nil {
				t.Fatal(err)
			}
			if kind == "unowned" {
				h.fp.AddUnowned(inst.Name)
			} else {
				if err := h.fp.Create(context.Background(), provider.Spec{Name: inst.Name, Meta: provider.Metadata{ControllerID: h.store.ControllerID(), InstanceID: inst.ID}}); err != nil {
					t.Fatal(err)
				}
			}
			h.m.o.Providers["macos"] = uncertainDeletion{Provider: h.fp, statusErr: kind == "status error", deleteErr: kind == "delete error", noDelete: kind == "delete did nothing"}
			h.m.teardown(context.Background(), inst, "test")
			got, ok := h.store.Get(inst.ID)
			if !ok || got.Phase == state.PhaseDeregistering || !got.GuestDeletedAt.IsZero() {
				t.Fatal("released uncertain guest")
			}
			if cap, _ := h.m.rawCapacity(context.Background(), "macos"); cap != 0 {
				t.Fatalf("reserved capacity %d", cap)
			}
		})
	}
}

func TestPendingCleanupGetsOnlyOneRecoverySweep(t *testing.T) {
	h := newHarnessSweep(t, func(c *config.Config) { c.Budget.MaxInstances = 1 }, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.m.accepting.Store(true)
	pending := &state.Instance{ID: "pending", Name: "bivouac-macos-pending", Provider: "macos", ScaleSetID: 100, Phase: state.PhaseDeregistering, CleanupPending: true, GuestDeletedAt: time.Now().Add(-time.Second), CreatedAt: time.Now(), Job: &state.Job{RunID: 1}}
	if err := h.store.Put(pending); err != nil {
		t.Fatal(err)
	}
	p := &poller{name: "macos"}
	h.m.converge(ctx, nil, p, 100, &github.Statistics{TotalAssignedJobs: 1, TotalRunningJobs: 1}, nil)
	h.eventually("recovery sweep boots despite old job statistics", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	sweep := h.instanceNamed(state.PhaseBooting)
	if !sweep.Sweep {
		t.Fatal("replacement not marked as sweep")
	}
	h.fp.MarkReady(sweep.Name)
	h.eventually("sweep listens", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
	// Retire it without receiving a job. Repeated empty polls must not create
	// more guests just because the same old registration remains busy.
	h.m.stopRun(sweep.ID)
	h.eventually("sweep removed", func() bool { _, ok := h.store.Get(sweep.ID); return !ok })
	for range 3 {
		h.m.converge(ctx, nil, p, 100, &github.Statistics{TotalAssignedJobs: 1, TotalRunningJobs: 1}, nil)
	}
	if len(h.store.List()) != 1 || len(h.fp.Names()) != 0 {
		t.Fatal("pending cleanup repeatedly provisioned sweep guests")
	}
	h.m.Wait()
}

func TestTerminalJobPendingDeregistrationCannotHideNewAssignedWork(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Budget.MaxInstances = 1 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.m.accepting.Store(true)
	pending := &state.Instance{ID: "pending", Name: "bivouac-macos-pending", Provider: "macos", ScaleSetID: 100, Phase: state.PhaseDeregistering, CleanupPending: true, GuestDeletedAt: time.Now(), CreatedAt: time.Now(), Job: &state.Job{RunID: 1}}
	if err := h.store.Put(pending); err != nil {
		t.Fatal(err)
	}
	h.m.converge(ctx, nil, &poller{name: "macos"}, 100, &github.Statistics{TotalAssignedJobs: 1, TotalRunningJobs: 0}, nil)
	h.eventually("new demand despite terminal job's retained registration", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	cancel()
	h.m.Wait()
}

func TestConcurrentAdmissionsRespectGuestAndCleanupRecordBudgets(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Budget.MaxInstances = 1 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.m.accepting.Store(true)
	if err := h.store.Put(&state.Instance{ID: "pending", Provider: "macos", Phase: state.PhaseDeregistering, CleanupPending: true, GuestDeletedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	successes := make(chan struct{}, 12)
	for range 12 {
		wg.Go(func() {
			if _, err := h.m.launch(ctx, "macos", 100, false); err == nil {
				successes <- struct{}{}
			}
		})
	}
	wg.Wait()
	if len(successes) != 1 || len(h.store.List()) != 2 {
		t.Fatal("concurrent admissions exceeded durable resource budgets")
	}
	cancel()
	h.m.Wait()
}
