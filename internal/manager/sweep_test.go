package manager

import (
	"context"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/state"
)

func TestSweepOnOpenAndAfterLabelRoutedJob(t *testing.T) {
	h := newHarnessSweep(t, func(c *config.Config) { c.Budget.SweepIdleTimeout.Duration = 300 * time.Millisecond }, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)

	// Opening the session with nothing assigned still starts one sweep runner.
	h.eventually("sweep guest", func() bool { i := h.instanceNamed(""); return i != nil && i.Sweep })
	sweep := h.instanceNamed("")
	h.fp.MarkReady(sweep.Name)
	h.eventually("sweep listening", func() bool { i, _ := h.store.Get(sweep.ID); return i != nil && i.Phase == state.PhaseListening })

	// It picks up a job GitHub routed by label (never assigned to the scale
	// set), so another sweep must follow once it is done.
	h.gh.Push(&github.Message{MessageID: 1, JobStartedMessages: []*scalesetJobStarted{github.JobStarted(77, sweep.Name)}, Statistics: &github.Statistics{}})
	h.fp.MarkJobRunning(sweep.Name)
	h.eventually("sweep running a job", func() bool { i, _ := h.store.Get(sweep.ID); return i != nil && i.Job != nil })
	h.gh.Push(&github.Message{MessageID: 2, JobCompletedMessages: []*scalesetJobCompleted{github.JobCompleted(77, sweep.Name, "succeeded")}, Statistics: &github.Statistics{}})
	h.fp.ExitRunner(sweep.Name, 0)
	h.eventually("first sweep gone", func() bool { _, ok := h.store.Get(sweep.ID); return !ok })
	h.gh.Push(&github.Message{MessageID: 3, Statistics: &github.Statistics{}})
	h.eventually("second sweep", func() bool { i := h.instanceNamed(""); return i != nil && i.Sweep && i.ID != sweep.ID })
	second := h.instanceNamed("")
	h.fp.MarkReady(second.Name)
	// Nothing queued this time: the sweep retires on its short idle timeout.
	h.eventually("second sweep retired", func() bool { return len(h.fp.Names()) == 0 })
	h.gh.Push(&github.Message{MessageID: 4, Statistics: &github.Statistics{}})
	time.Sleep(150 * time.Millisecond)
	if n := len(h.store.List()); n != 0 {
		t.Fatalf("a third sweep started with nothing to find: %d", n)
	}

	// An assigned job whose runner starts that same run is not a mismatch.
	h.gh.Push(&github.Message{MessageID: 5, JobAssignedMessages: []*scalesetJobAssigned{github.JobAssigned(88)}, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
	h.eventually("assigned guest", func() bool { i := h.instanceNamed(""); return i != nil && !i.Sweep })
	inst := h.instanceNamed("")
	h.fp.MarkReady(inst.Name)
	h.eventually("listening", func() bool { i, _ := h.store.Get(inst.ID); return i != nil && i.Phase == state.PhaseListening })
	h.gh.Push(&github.Message{MessageID: 6, JobStartedMessages: []*scalesetJobStarted{github.JobStarted(88, inst.Name)}, Statistics: &github.Statistics{TotalAssignedJobs: 1, TotalRunningJobs: 1}})
	h.fp.MarkJobRunning(inst.Name)
	h.gh.Push(&github.Message{MessageID: 7, JobCompletedMessages: []*scalesetJobCompleted{github.JobCompleted(88, inst.Name, "succeeded")}, Statistics: &github.Statistics{}})
	h.fp.ExitRunner(inst.Name, 0)
	h.eventually("assigned guest gone", func() bool { _, ok := h.store.Get(inst.ID); return !ok })
	h.gh.Push(&github.Message{MessageID: 8, Statistics: &github.Statistics{}})
	time.Sleep(150 * time.Millisecond)
	if n := len(h.store.List()); n != 0 {
		t.Fatalf("a sweep started after a correctly assigned job: %d", n)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDrainKeepsSessionWithZeroCapacity(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeDrain)
	done := h.run(ctx)
	h.eventually("polling while drained", func() bool { return h.m.Polling() && h.m.Phase() == "idle" })
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 2}})
	time.Sleep(150 * time.Millisecond)
	if n := len(h.store.List()); n != 0 {
		t.Fatalf("drained daemon launched %d guest(s)", n)
	}
	if c, _ := h.m.capacity(ctx, "macos"); c != 0 {
		t.Fatalf("capacity while drained = %d", c)
	}
	h.setMode(control.ModeOn)
	h.eventually("polling after on", func() bool { return h.m.Phase() == "polling" })
	h.gh.Push(&github.Message{MessageID: 2, Statistics: &github.Statistics{TotalAssignedJobs: 2}})
	h.eventually("guests after on", func() bool { return len(h.store.List()) == 2 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
