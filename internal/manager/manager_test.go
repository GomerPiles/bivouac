package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/hostinfo"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/fake"
	"github.com/GomerPiles/bivouac/internal/state"
)

type harness struct {
	t     *testing.T
	m     *Manager
	fp    *fake.Provider
	gh    *github.Fake
	files control.Files
	store *state.Store
	wake  chan struct{}
	dir   string
}

func newHarness(t *testing.T, mutate func(*config.Config)) *harness {
	return newHarnessSweep(t, mutate, false)
}

func newHarnessSweep(t *testing.T, mutate func(*config.Config), sweep bool) *harness {
	t.Helper()
	cfg, err := config.Parse([]byte(config.Example))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Budget.MaxInstances = 2
	cfg.Budget.IdleTimeout.Duration = 400 * time.Millisecond
	cfg.Budget.ReadyTimeout.Duration = 2 * time.Second
	p := cfg.Providers["macos"]
	p.MaxInstances = 2
	p.VZ.ForeignSlots = 0
	p.VZ.CPU, p.VZ.MemoryGB = 0, 0
	cfg.Providers["macos"] = p
	if mutate != nil {
		mutate(cfg)
	}
	dir := t.TempDir()
	store, err := state.Open(dir, func() string { return "ctl-test" })
	if err != nil {
		t.Fatal(err)
	}
	fp := fake.New("macos", "ctl-test")
	gh := github.NewFake()
	var n atomic.Int32
	wake := make(chan struct{}, 1)
	files := control.Files{Dir: dir}
	m, err := New(Options{
		Config: cfg, Store: store, Files: files, Providers: map[string]provider.Provider{"macos": fp}, GitHub: gh, JIT: gh,
		Host: hostinfo.Info{CPUs: 10, MemoryBytes: 32 << 30}, Log: slog.New(slog.NewTextHandler(os.Stderr, nil)),
		LogDir: dir, DiagDir: filepath.Join(dir, "diag"), Wake: wake,
		NewID:        func() string { return fmt.Sprintf("i%d", n.Add(1)) },
		PollInterval: 20 * time.Millisecond, Tick: 20 * time.Millisecond, SurplusGrace: 100 * time.Millisecond, CleanupRetry: 20 * time.Millisecond, NoSweep: !sweep,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, m: m, fp: fp, gh: gh, files: files, store: store, wake: wake, dir: dir}
}

func (h *harness) setMode(m control.Mode) {
	if err := h.files.WriteMode(m); err != nil {
		h.t.Fatal(err)
	}
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// eventually polls cond for up to 5s.
func (h *harness) eventually(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %s", what)
}

func (h *harness) instanceNamed(phase state.Phase) *state.Instance {
	for _, inst := range h.store.List() {
		if phase == "" || inst.Phase == phase {
			return inst
		}
	}
	return nil
}

func (h *harness) run(ctx context.Context) <-chan error {
	done := make(chan error, 1)
	go func() { done <- h.m.Run(ctx) }()
	return done
}

func TestOneJobPerGuest(t *testing.T) {
	for _, providerType := range []string{"vz", "crosvm", "hcs"} {
		t.Run(providerType, func(t *testing.T) { testOneJobPerGuest(t, providerType) })
	}
}

func testOneJobPerGuest(t *testing.T, providerType string) {
	h := newHarness(t, func(c *config.Config) {
		p := c.Providers["macos"]
		p.Type = providerType
		switch providerType {
		case "hcs":
			p.VZ = nil
			p.HCS = &config.HCS{Image: "fixture", CPU: 4, MemoryGB: 8}
		case "crosvm":
			p.VZ = nil
			p.Crosvm = &config.Crosvm{BaselineName: "fixture"}
		}
		c.Providers["macos"] = p
	})
	var stageLog bytes.Buffer
	h.m.o.Log = slog.New(slog.NewJSONHandler(&stageLog, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)

	// GitHub offers a job and reports one assigned job.
	h.gh.Push(&github.Message{MessageID: 1, JobAvailableMessages: []*scalesetJobAvailable{github.JobAvailable(501, "example")}, Statistics: &github.Statistics{TotalAvailableJobs: 1, TotalAssignedJobs: 1}})
	h.eventually("guest created", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	inst := h.instanceNamed(state.PhaseBooting)
	h.eventually("job acquired", func() bool { got := h.gh.AcquiredIDs(); return len(got) == 1 && got[0] == 501 })
	if !strings.HasPrefix(inst.Name, "bivouac-macos-") {
		t.Fatalf("name %q lacks prefix", inst.Name)
	}
	h.fp.MarkReady(inst.Name)
	h.eventually("runner listening", func() bool { i, _ := h.store.Get(inst.ID); return i != nil && i.Phase == state.PhaseListening })
	fi, _ := h.fp.Get(inst.Name)
	if string(fi.JIT) == "" || fi.Spec.Meta.ControllerID != "ctl-test" {
		t.Fatalf("runner started without JIT or metadata: %+v", fi.Spec.Meta)
	}

	// The job starts on our runner, runs, completes; the runner exits.
	h.gh.Push(&github.Message{MessageID: 2, JobStartedMessages: []*scalesetJobStarted{github.JobStarted(501, inst.Name)}, Statistics: &github.Statistics{TotalAssignedJobs: 1, TotalRunningJobs: 1}})
	h.fp.MarkJobRunning(inst.Name)
	h.eventually("job bound", func() bool {
		i, _ := h.store.Get(inst.ID)
		return i != nil && i.Job != nil && i.Phase == state.PhaseRunning
	})
	h.gh.Push(&github.Message{MessageID: 3, JobCompletedMessages: []*scalesetJobCompleted{github.JobCompleted(501, inst.Name, "succeeded")}, Statistics: &github.Statistics{}})
	h.fp.ExitRunner(inst.Name, 0)
	h.eventually("guest torn down", func() bool { _, ok := h.store.Get(inst.ID); return !ok })
	if names := h.fp.Names(); len(names) != 0 {
		t.Fatalf("guests left: %v", names)
	}
	if entries, _ := os.ReadDir(filepath.Join(h.dir, "diag")); len(entries) != 1 {
		t.Fatalf("diagnostics not collected: %v", entries)
	}
	if h.gh.Registered(inst.Name) {
		t.Fatal("runner still registered")
	}
	// Idle: no guest running while on.
	if len(h.fp.Names()) != 0 || !h.m.Polling() {
		t.Fatal("expected polling with no guests")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	stages := map[string]bool{}
	decoder := json.NewDecoder(&stageLog)
	for decoder.More() {
		var record struct {
			Message    string `json:"msg"`
			Provider   string `json:"provider"`
			Stage      string `json:"stage"`
			DurationMS int64  `json:"duration_ms"`
			Success    bool   `json:"success"`
		}
		if err := decoder.Decode(&record); err != nil {
			t.Fatal(err)
		}
		if record.Stage != "" {
			if record.Message != "startup stage" || record.Provider != inst.Provider || !record.Success || record.DurationMS < 0 {
				t.Fatal("invalid registration timing")
			}
			stages[record.Stage] = true
		}
	}
	if !stages["jit_generation"] || !stages["listener_wait"] {
		t.Fatal("registration stages missing")
	}
}

func TestBudgetCapsConcurrency(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Budget.MaxInstances = 1 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 3}})
	h.eventually("one guest", func() bool { return len(h.store.List()) == 1 })
	time.Sleep(100 * time.Millisecond)
	if n := len(h.store.List()); n != 1 {
		t.Fatalf("budget exceeded: %d guests", n)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestForeignGuestConsumesHostSlot(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		p := c.Providers["macos"]
		p.VZ.HostVMLimit = 2
		c.Providers["macos"] = p
	})
	h.fp.AddForeign("tartelet-clone")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 2}})
	h.eventually("one guest", func() bool { return len(h.store.List()) == 1 })
	time.Sleep(100 * time.Millisecond)
	if n := len(h.store.List()); n != 1 {
		t.Fatalf("host VM limit exceeded with a foreign guest running: %d", n)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDrainFinishesActiveJobThenIdles(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
	h.eventually("guest", func() bool { return h.instanceNamed("") != nil })
	inst := h.instanceNamed("")
	h.fp.MarkReady(inst.Name)
	h.eventually("listening", func() bool { i, _ := h.store.Get(inst.ID); return i != nil && i.Phase == state.PhaseListening })
	h.gh.Push(&github.Message{MessageID: 2, JobStartedMessages: []*scalesetJobStarted{github.JobStarted(7, inst.Name)}, Statistics: &github.Statistics{TotalAssignedJobs: 1, TotalRunningJobs: 1}})
	h.fp.MarkJobRunning(inst.Name)
	h.eventually("running", func() bool { i, _ := h.store.Get(inst.ID); return i != nil && i.Phase == state.PhaseRunning })

	h.setMode(control.ModeDrain)
	h.eventually("draining", func() bool { return h.m.Phase() == "draining" })
	// A new assigned job must not start a guest while draining.
	time.Sleep(100 * time.Millisecond)
	if _, ok := h.store.Get(inst.ID); !ok {
		t.Fatal("drain killed the active job")
	}
	if len(h.store.List()) != 1 {
		t.Fatal("drain started a new guest")
	}
	h.fp.ExitRunner(inst.Name, 0)
	h.eventually("idle", func() bool { return h.m.Phase() == "idle" && len(h.fp.Names()) == 0 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStopReclaimsImmediately(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
	h.eventually("guest", func() bool { return h.instanceNamed("") != nil })
	inst := h.instanceNamed("")
	h.fp.MarkReady(inst.Name)
	h.fp.MarkJobRunning(inst.Name)
	h.eventually("running", func() bool {
		i, _ := h.store.Get(inst.ID)
		return i != nil && (i.Phase == state.PhaseRunning || i.Phase == state.PhaseListening)
	})

	h.setMode(control.ModeStop)
	h.eventually("torn down", func() bool { return len(h.fp.Names()) == 0 && h.m.Phase() == "idle" })
	if h.gh.Registered(inst.Name) {
		t.Fatal("runner left registered after stop")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStopRetriesBusyRegistrationWithoutRestart(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
	h.eventually("guest", func() bool { return h.instanceNamed("") != nil })
	inst := h.instanceNamed("")
	h.fp.MarkReady(inst.Name)
	h.eventually("listening", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
	h.fp.MarkJobRunning(inst.Name)
	h.gh.SetRemoveError(errors.New("job still running"))
	h.setMode(control.ModeStop)
	h.eventually("guest removed with cleanup retained", func() bool {
		return len(h.fp.Names()) == 0 && h.instanceNamed(state.PhaseDeregistering) != nil
	})
	if !h.gh.Registered(inst.Name) {
		t.Fatal("registration should still be busy")
	}
	if !contains(h.fp.CallLog(), "stop-runner "+inst.Name) {
		t.Fatal("official runner was not asked to report cancellation")
	}
	h.gh.SetRemoveError(nil)
	h.eventually("cleanup retried", func() bool { return len(h.store.List()) == 0 && !h.gh.Registered(inst.Name) })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRestartRetriesRetainedCleanup(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
	h.eventually("guest", func() bool { return h.instanceNamed("") != nil })
	inst := h.instanceNamed("")
	h.fp.MarkReady(inst.Name)
	h.eventually("listening", func() bool { return h.instanceNamed(state.PhaseListening) != nil })
	h.gh.SetRemoveError(errors.New("service unavailable"))
	h.setMode(control.ModeStop)
	h.eventually("retained cleanup", func() bool { return len(h.fp.Names()) == 0 && h.instanceNamed(state.PhaseDeregistering) != nil })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, ok := h.store.Get(inst.ID); !ok {
		t.Fatal("shutdown lost the pending registration")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done = h.run(ctx2)
	h.eventually("cleanup tracked after restart", func() bool { return h.m.activeCount() == 1 })
	h.gh.SetRemoveError(nil)
	h.eventually("registration removed after restart", func() bool { return len(h.store.List()) == 0 && !h.gh.Registered(inst.Name) })
	cancel2()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOffExitsWhenIdle(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOff)
	done := h.run(ctx)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not exit in off mode")
	}
	s, _ := h.files.ReadStatus()
	if s == nil || s.Phase != "exiting" {
		t.Fatalf("status = %+v", s)
	}
}

func TestIdleRunnerRetired(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
	h.eventually("guest", func() bool { return h.instanceNamed("") != nil })
	inst := h.instanceNamed("")
	h.fp.MarkReady(inst.Name)
	h.eventually("listening", func() bool { i, _ := h.store.Get(inst.ID); return i != nil && i.Phase == state.PhaseListening })
	// The job was cancelled elsewhere: nothing assigned any more.
	h.gh.Push(&github.Message{MessageID: 2, Statistics: &github.Statistics{}})
	h.eventually("retired", func() bool { return len(h.fp.Names()) == 0 && !h.gh.Registered(inst.Name) })
	if h.gh.Registered(inst.Name) {
		t.Fatal("idle runner still registered")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestVMDeathMidJobRecovers(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
	h.eventually("guest", func() bool { return h.instanceNamed("") != nil })
	inst := h.instanceNamed("")
	h.fp.MarkReady(inst.Name)
	h.eventually("listening", func() bool { i, _ := h.store.Get(inst.ID); return i != nil && i.Phase == state.PhaseListening })
	h.fp.Kill(inst.Name)
	h.eventually("cleaned", func() bool { _, ok := h.store.Get(inst.ID); return !ok && len(h.fp.Names()) == 0 })
	if h.gh.Registered(inst.Name) {
		t.Fatal("dead VM's runner still registered")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestControllerRestartReconciles(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
	h.eventually("guest", func() bool { return h.instanceNamed("") != nil })
	inst := h.instanceNamed("")
	h.fp.MarkReady(inst.Name)
	h.eventually("listening", func() bool { i, _ := h.store.Get(inst.ID); return i != nil && i.Phase == state.PhaseListening })
	// Controller dies: context cancelled, guest keeps running.
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(h.fp.Names()) != 1 {
		t.Fatal("guest should survive a controller crash")
	}
	// Plant an orphan with our metadata and an unrelated VM to prove cleanup scope.
	_ = h.fp.Create(context.Background(), provider.Spec{Name: "bivouac-macos-orphan", Baseline: "ci-macos", Meta: provider.Metadata{ControllerID: "ctl-test", InstanceID: "gone"}})
	h.fp.AddUnowned("bivouac-macos-notours")
	h.fp.AddUnowned("ci-macos")

	// Restart: the running guest is adopted, the orphan deleted, the rest untouched.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done = h.run(ctx2)
	h.eventually("orphan deleted", func() bool {
		names := h.fp.Names()
		return len(names) == 3 && !contains(names, "bivouac-macos-orphan")
	})
	if _, ok := h.store.Get(inst.ID); !ok {
		t.Fatal("running guest was not adopted")
	}
	h.fp.MarkJobRunning(inst.Name)
	h.fp.ExitRunner(inst.Name, 0)
	h.eventually("adopted guest finished", func() bool { _, ok := h.store.Get(inst.ID); return !ok })
	names := h.fp.Names()
	if !contains(names, "bivouac-macos-notours") || !contains(names, "ci-macos") {
		t.Fatalf("cleanup touched unrelated guests: %v", names)
	}
	for _, c := range h.fp.CallLog() {
		if strings.Contains(c, "delete ci-macos") || strings.Contains(c, "delete bivouac-macos-notours") {
			t.Fatalf("forbidden call %q", c)
		}
	}
	cancel2()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestJITFailureTearsDown(t *testing.T) {
	h := newHarness(t, nil)
	h.gh.FailJIT = errors.New("api down")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.gh.Push(&github.Message{MessageID: 1, Statistics: &github.Statistics{TotalAssignedJobs: 1}})
	h.eventually("guest", func() bool { return h.instanceNamed("") != nil })
	inst := h.instanceNamed("")
	h.fp.MarkReady(inst.Name)
	h.eventually("torn down", func() bool { _, ok := h.store.Get(inst.ID); return !ok })
	if errs := h.store.Errors(); len(errs) == 0 || !strings.Contains(errs[0].Message, "api down") {
		t.Fatalf("error not recorded: %v", errs)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
