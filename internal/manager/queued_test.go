package manager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

func queuedConfig(c *config.Config) {
	jitConfig(c)
	c.GitHub.Demand = config.DemandQueued
	c.GitHub.QueueRepositories = []string{"example-org/repo"}
	p := c.Providers["macos"]
	p.IdlePool = 0
	p.Labels = []string{"self-hosted", "Windows", "X64", "bivouac-test"}
	c.Providers["macos"] = p
}

func queuedFixtureJob(id int64) github.QueuedJob {
	return github.QueuedJob{ID: id, Status: "queued", Labels: []string{"SELF-HOSTED", "windows", "bivouac-test"}}
}

func TestQueuedDemandStartsOnlyForJobsAndReturnsToZero(t *testing.T) {
	h := newHarness(t, queuedConfig)
	h.m.o.GitHub = nil
	h.m.o.QueuePollInterval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	time.Sleep(120 * time.Millisecond)
	if len(h.store.List()) != 0 {
		t.Fatal("empty queue created a warm guest")
	}
	h.gh.SetQueuedJobs([]github.QueuedJob{queuedFixtureJob(1)}, nil)
	h.eventually("queue starts guest", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	first := h.instanceNamed(state.PhaseBooting)
	time.Sleep(100 * time.Millisecond)
	if len(h.store.List()) != 1 {
		t.Fatal("repeated queue reads duplicated a provisioning guest")
	}
	h.fp.MarkReady(first.Name)
	h.eventually("runner listening", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
	h.fp.SetRunnerJob(first.Name, provider.RunnerJob{RunID: 123, Repository: "example-org/repo", Name: "test"})
	h.gh.SetQueuedJobs(nil, nil)
	h.eventually("job running", func() bool { return h.instanceNamed(state.PhaseRunning) != nil })
	time.Sleep(120 * time.Millisecond)
	if len(h.fp.Names()) != 1 {
		t.Fatal("empty queue interrupted the running job")
	}
	h.fp.ExitRunner(first.Name, 0)
	h.eventually("finished job removed", func() bool { return len(h.store.List()) == 0 })
	time.Sleep(120 * time.Millisecond)
	if len(h.fp.Names()) != 0 {
		t.Fatal("finished job replenished an idle pool")
	}
	h.gh.SetQueuedJobs([]github.QueuedJob{queuedFixtureJob(2)}, nil)
	h.eventually("new job starts a fresh guest", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	second := h.instanceNamed(state.PhaseBooting)
	if first.Name == second.Name {
		t.Fatal("reused the completed guest")
	}
	h.fp.MarkReady(second.Name)
	h.eventually("replacement listening", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
	h.gh.SetQueuedJobs(nil, nil)
	h.eventually("cancelled demand retires idle guest", func() bool { return len(h.store.List()) == 0 })
	h.setMode(control.ModeOff)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestQueuedDemandFailuresAndBusyWithdrawalAreSafe(t *testing.T) {
	h := newHarness(t, queuedConfig)
	h.m.o.QueuePollInterval = 20 * time.Millisecond
	h.gh.SetQueuedJobs([]github.QueuedJob{queuedFixtureJob(1)}, errors.New("queue unavailable"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	time.Sleep(120 * time.Millisecond)
	if len(h.store.List()) != 0 {
		t.Fatal("failed queue read launched a guest")
	}
	h.gh.SetQueuedJobs([]github.QueuedJob{queuedFixtureJob(1)}, nil)
	h.eventually("queue recovered", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	inst := h.instanceNamed(state.PhaseBooting)
	h.fp.MarkReady(inst.Name)
	h.eventually("listening", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
	h.gh.SetRemoveError(errors.New("runner busy"))
	h.gh.SetQueuedJobs(nil, nil)
	time.Sleep(200 * time.Millisecond)
	if len(h.fp.Names()) != 1 {
		t.Fatal("deleted a registration that could have accepted work")
	}
	h.fp.SetRunnerJob(inst.Name, provider.RunnerJob{RunID: 456, Repository: "example-org/repo", Name: "test"})
	h.eventually("busy race becomes running", func() bool { return h.instanceNamed(state.PhaseRunning) != nil })
	h.gh.SetRemoveError(nil)
	h.setMode(control.ModeDrain)
	time.Sleep(100 * time.Millisecond)
	if len(h.fp.Names()) != 1 {
		t.Fatal("drain interrupted the accepted job")
	}
	h.fp.ExitRunner(inst.Name, 0)
	h.eventually("drained", func() bool { return len(h.store.List()) == 0 })
	h.setMode(control.ModeOff)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestQueuedRoutingRequiresEveryLabelAndAvoidsDoubleCounting(t *testing.T) {
	c, err := config.Parse([]byte(config.Example))
	if err != nil {
		t.Fatal(err)
	}
	queuedConfig(c)
	c.Providers["overlap"] = c.Providers["macos"]
	wrong := queuedFixtureJob(2)
	wrong.Labels = append(wrong.Labels, "unavailable")
	busy := queuedFixtureJob(3)
	busy.Runner = 42
	group := queuedFixtureJob(4)
	group.Group = "another-group"
	counts := queuedCounts([]github.QueuedJob{queuedFixtureJob(1), queuedFixtureJob(1), wrong, busy, group}, c)
	if counts["macos"] != 1 || counts["overlap"] != 0 {
		t.Fatalf("routing admitted unexpected demand: %v", counts)
	}
}

type blockedQueue struct{ *github.Fake }

func (q blockedQueue) QueuedJobs(ctx context.Context, _ []string) ([]github.QueuedJob, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestQueuedPollDoesNotHoldDrainOrShutdown(t *testing.T) {
	h := newHarness(t, queuedConfig)
	h.m.o.JIT = blockedQueue{h.gh}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.eventually("queue polling", func() bool { return h.m.Phase() == "waiting for queued jobs" })
	h.setMode(control.ModeDrain)
	h.eventually("drained despite hung queue", func() bool { return h.m.Phase() == "idle" })
	h.setMode(control.ModeOff)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queue poller held shutdown")
	}
}

func TestQueuedCancellationDuringBootSkipsRegistration(t *testing.T) {
	h := newHarness(t, queuedConfig)
	h.m.o.QueuePollInterval = 20 * time.Millisecond
	h.gh.SetQueuedJobs([]github.QueuedJob{queuedFixtureJob(1)}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.eventually("boot", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	inst := h.instanceNamed(state.PhaseBooting)
	h.gh.SetQueuedJobs(nil, nil)
	h.eventually("cancellation observed", func() bool { return !h.m.queueWaiting("macos") })
	h.fp.MarkReady(inst.Name)
	h.eventually("cancelled guest removed", func() bool { return len(h.store.List()) == 0 })
	if len(h.gh.JITNames()) != 0 {
		t.Fatal("registered a runner after its demand disappeared during boot")
	}
	h.setMode(control.ModeOff)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
