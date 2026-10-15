package manager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/state"
)

// Surplus retirement withdraws the registration first; a busy rejection
// means GitHub just assigned a job, so the runner is kept.
func TestSurplusRetirementDeregistersFirst(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	h.m.accepting.Store(true)
	name := "bivouac-macos-idle"
	jit, err := h.gh.GenerateJIT(ctx, 100, name, "_work")
	if err != nil {
		t.Fatal(err)
	}
	inst := &state.Instance{ID: "idle", Name: name, Provider: "macos", ScaleSetID: 100, RunnerID: jit.RunnerID, Phase: state.PhaseListening, CreatedAt: time.Now(), ListenedAt: time.Now().Add(-time.Minute)}
	if err := h.store.Put(inst); err != nil {
		t.Fatal(err)
	}
	r := &run{inst: inst, cancel: func() {}, stopNow: make(chan struct{})}
	h.m.mu.Lock()
	h.m.runs[inst.ID] = r
	h.m.mu.Unlock()
	p := &poller{name: "macos", assigned: map[int64]bool{}}

	h.gh.SetRunnerRemoveError(jit.RunnerID, errors.New("runner is busy"))
	h.m.converge(ctx, nil, p, 100, &github.Statistics{}, nil)
	if r.stopRequested() || !h.gh.Registered(name) {
		t.Fatal("busy surplus runner was stopped")
	}

	h.gh.SetRunnerRemoveError(jit.RunnerID, nil)
	h.m.converge(ctx, nil, p, 100, &github.Statistics{}, nil)
	if !r.stopRequested() || h.gh.Registered(name) {
		t.Fatal("idle surplus runner not withdrawn and retired")
	}
}

func TestReconnectBackoffResetsAfterHealthySession(t *testing.T) {
	b := time.Second
	var waits []time.Duration
	for _, healthy := range []bool{false, false, false, true, false} {
		var w time.Duration
		w, b = reconnectDelay(b, healthy)
		waits = append(waits, w)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, time.Second, 2 * time.Second}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("waits = %v, want %v", waits, want)
		}
	}
	b = time.Minute
	if w, next := reconnectDelay(b, false); w != time.Minute || next != time.Minute {
		t.Fatalf("cap: %v %v", w, next)
	}
}
