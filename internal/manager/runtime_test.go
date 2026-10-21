package manager

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/fake"
	"github.com/GomerPiles/bivouac/internal/state"
)

type runtimeProvider struct {
	provider.Provider
	activate   func(context.Context) error
	deactivate func(context.Context) error
	list       func(context.Context) ([]provider.Owned, []provider.Foreign, error)
}

func (p *runtimeProvider) Activate(ctx context.Context) error { return p.activate(ctx) }
func (p *runtimeProvider) Deactivate(ctx context.Context) error {
	if p.deactivate != nil {
		return p.deactivate(ctx)
	}
	return nil
}
func (p *runtimeProvider) List(ctx context.Context) ([]provider.Owned, []provider.Foreign, error) {
	if p.list != nil {
		return p.list(ctx)
	}
	return p.Provider.List(ctx)
}

func TestRuntimeStartupWithoutRecordsActivatesBeforeLaunch(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.GitHub.Demand = config.DemandJIT
		p := c.Providers["macos"]
		p.IdlePool = 1
		c.Providers["macos"] = p
	})
	var activated atomic.Int32
	rp := &runtimeProvider{Provider: h.fp, activate: func(ctx context.Context) error {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > runtimeTimeout {
			return errors.New("missing activation deadline")
		}
		activated.Add(1)
		return nil
	}}
	rp.list = func(ctx context.Context) ([]provider.Owned, []provider.Foreign, error) {
		if activated.Load() == 0 {
			return nil, nil, errors.New("runtime stopped")
		}
		return h.fp.List(ctx)
	}
	var deactivated atomic.Int32
	rp.deactivate = func(context.Context) error { deactivated.Add(1); return nil }
	h.m.o.Providers["macos"] = rp
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.eventually("first launch after activation", func() bool { return len(h.fp.Names()) == 1 })
	if activated.Load() != 1 {
		t.Fatal("startup activation was repeated")
	}
	cancel()
	if err := <-done; err != nil || deactivated.Load() != 0 {
		t.Fatal("signal deactivated host", err, deactivated.Load())
	}
}

func TestRuntimeStartupUnavailableWithoutRecords(t *testing.T) {
	for _, mode := range []control.Mode{control.ModeOff, control.ModeDrain, control.ModeStop} {
		t.Run(string(mode), func(t *testing.T) {
			h := newHarness(t, nil)
			var starts, stops atomic.Int32
			h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp,
				activate:   func(context.Context) error { starts.Add(1); return errors.New("down") },
				deactivate: func(context.Context) error { stops.Add(1); return nil },
				list: func(context.Context) ([]provider.Owned, []provider.Foreign, error) {
					return nil, nil, errors.New("runtime down")
				},
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			h.setMode(mode)
			done := h.run(ctx)
			if mode != control.ModeOff {
				h.eventually("idle", func() bool { return h.m.Phase() == "idle" })
				cancel()
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			wantStops := int32(0)
			if mode == control.ModeOff {
				wantStops = 1
			}
			if starts.Load() != 0 || stops.Load() != wantStops {
				t.Fatal("unexpected lifecycle", starts.Load(), stops.Load())
			}
		})
	}
}

func TestRuntimeStartupActivationFailure(t *testing.T) {
	for _, mode := range []control.Mode{control.ModeOn, control.ModeOff, control.ModeDrain} {
		t.Run(string(mode), func(t *testing.T) {
			h := newHarness(t, nil)
			if err := h.store.Put(&state.Instance{ID: "retained", Provider: "macos", Name: "bivouac-macos-retained", Phase: state.PhaseRunning, ScaleSetID: 1}); err != nil {
				t.Fatal(err)
			}
			failure := errors.New("activation failed")
			h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp, activate: func(context.Context) error { return failure }}
			h.setMode(mode)
			err := h.m.Run(t.Context())
			var activationErr *ActivationError
			if !errors.Is(err, failure) || !errors.As(err, &activationErr) {
				t.Fatal("startup did not fail", err)
			}
			if len(h.store.List()) != 1 {
				t.Fatal("retained record lost")
			}
		})
	}
}

func TestRuntimeAsyncGatingRetryAndOtherProvider(t *testing.T) {
	h := newHarness(t, nil)
	var calls atomic.Int32
	fail := atomic.Bool{}
	fail.Store(true)
	h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp, activate: func(context.Context) error {
		calls.Add(1)
		if fail.Load() {
			return errors.New("unavailable")
		}
		return nil
	}}
	other := h.m.o.Config.Providers["macos"]
	other.ScaleSet = "bivouac-other"
	h.m.o.Config.Providers["other"] = other
	h.m.o.Providers["other"] = fake.New("other", h.store.ControllerID())
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); h.m.Wait() }()
	h.m.accepting.Store(true)
	if _, err := h.m.launch(ctx, "macos", 1, true); err == nil {
		t.Fatal("inactive provider launched")
	}
	if _, err := h.m.launch(ctx, "other", 1, false); err != nil {
		t.Fatal("non-Activator blocked", err)
	}
	if !h.m.activateAsync(ctx, time.Now()) {
		t.Fatal("inactive provider not starting")
	}
	h.eventually("failed activation", func() bool {
		h.m.mu.Lock()
		defer h.m.mu.Unlock()
		return !h.m.runtimes["macos"].retry.IsZero()
	})
	h.m.mu.Lock()
	retry := h.m.runtimes["macos"].retry
	h.m.mu.Unlock()
	if time.Until(retry) < 29*time.Second {
		t.Fatal("activation retry too soon")
	}
	h.m.writeStatus(ctx, control.ModeOn)
	s, err := h.files.ReadStatus()
	if err != nil || s == nil || !strings.Contains(Describe(s, control.ModeOn, true), "activate provider macos: unavailable") {
		t.Fatal("activation failure missing from status", s, err)
	}
	h.m.activateAsync(ctx, retry.Add(-time.Nanosecond))
	if calls.Load() != 1 {
		t.Fatal("retried before backoff")
	}
	if _, err := h.m.launch(ctx, "macos", 1, false); err == nil {
		t.Fatal("failed provider launched")
	}
	fail.Store(false)
	h.m.activateAsync(ctx, retry)
	h.eventually("runtime active", func() bool { return h.m.runtimeActive("macos") })
	h.m.writeStatus(ctx, control.ModeOn)
	s, err = h.files.ReadStatus()
	if err != nil || s == nil || len(s.LastErrors) != 0 {
		t.Fatal("activation success did not clear status error", s, err)
	}
	if _, err := h.m.launch(ctx, "macos", 1, true); err != nil {
		t.Fatal("activated provider blocked", err)
	}
	if calls.Load() != 2 {
		t.Fatal("wrong retry count")
	}
}

func TestRuntimeOnStartupFailureWithoutGuestsDoesNotAbortOtherProviders(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.GitHub.Demand = config.DemandJIT
		p := c.Providers["macos"]
		p.IdlePool = 1
		c.Providers["macos"] = p
	})
	h.m.o.Config.Providers["other"] = h.m.o.Config.Providers["macos"]
	var calls atomic.Int32
	h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp,
		activate: func(context.Context) error { calls.Add(1); return errors.New("runtime unavailable") },
		list: func(context.Context) ([]provider.Owned, []provider.Foreign, error) {
			return nil, nil, errors.New("pipe unavailable")
		},
	}
	other := fake.New("other", h.store.ControllerID())
	h.m.o.Providers["other"] = other
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.eventually("other provider launch during failed activation", func() bool { return len(other.Names()) == 1 })
	h.eventually("activation failure status", func() bool {
		s, _ := h.files.ReadStatus()
		return s != nil && len(s.LastErrors) > 0 && s.Phase == "starting host runtimes"
	})
	if len(h.fp.Names()) != 0 || calls.Load() != 1 {
		t.Fatal("failed activation launched guests or ignored backoff")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal("On without guest records aborted", err)
	}
}

func TestRuntimeStartupWithGuestRecordsActivatesBeforeReconcile(t *testing.T) {
	h := newHarness(t, nil)
	if err := h.store.Put(&state.Instance{ID: "retained", Provider: "macos", Name: "bivouac-macos-retained", Phase: state.PhaseDestroying, ScaleSetID: 1}); err != nil {
		t.Fatal(err)
	}
	var active atomic.Bool
	var listed atomic.Bool
	h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp,
		activate: func(context.Context) error { active.Store(true); return nil },
		list: func(ctx context.Context) ([]provider.Owned, []provider.Foreign, error) {
			if !active.Load() {
				return nil, nil, errors.New("listed before startup activation")
			}
			listed.Store(true)
			return h.fp.List(ctx)
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h.setMode(control.ModeDrain)
	done := h.run(ctx)
	h.eventually("record reconciled", func() bool { return listed.Load() && len(h.store.List()) == 0 && h.m.Phase() == "idle" })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartupCancellationIsNotActivationFailure(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		h := newHarness(t, nil)
		if err := h.store.Put(&state.Instance{ID: "retained", Provider: "macos", Name: "bivouac-macos-retained", Phase: state.PhaseRunning, ScaleSetID: 1}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		if deadline {
			cancel()
			ctx, cancel = context.WithTimeout(t.Context(), 30*time.Millisecond)
		}
		h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp, activate: func(c context.Context) error {
			if !deadline {
				cancel()
			}
			<-c.Done()
			return c.Err()
		}}
		h.setMode(control.ModeOn)
		err := h.m.Run(ctx)
		cancel()
		var activationErr *ActivationError
		if err != ctx.Err() || errors.As(err, &activationErr) { //nolint:errorlint // The contract requires the exact, unwrapped context error.
			t.Fatal("startup signal wrapped as activation failure", err)
		}
	}
}

func TestRuntimeStartupDeregisteringOnlyNeedsNoHost(t *testing.T) {
	for _, mode := range []control.Mode{control.ModeOn, control.ModeOff, control.ModeDrain} {
		t.Run(string(mode), func(t *testing.T) {
			h := newHarness(t, nil)
			if err := h.store.Put(&state.Instance{ID: "cleanup", Provider: "macos", Name: "bivouac-macos-cleanup", Phase: state.PhaseDeregistering, ScaleSetID: 1}); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp,
				activate: func(context.Context) error { calls.Add(1); return errors.New("runtime unavailable") },
				list: func(context.Context) ([]provider.Owned, []provider.Foreign, error) {
					return nil, nil, errors.New("pipe down")
				},
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			h.setMode(mode)
			done := h.run(ctx)
			h.eventually("GitHub-only record cleaned up", func() bool { return len(h.store.List()) == 0 })
			if mode != control.ModeOff {
				if mode == control.ModeDrain && calls.Load() != 0 {
					t.Fatal("GitHub-only cleanup activated host")
				}
				cancel()
			}
			if err := <-done; err != nil {
				t.Fatal("GitHub-only cleanup required host", err)
			}
			if mode == control.ModeOff && calls.Load() != 0 {
				t.Fatal("Off GitHub-only cleanup activated host")
			}
		})
	}
}

func TestRuntimeAsyncDoesNotBlockModes(t *testing.T) {
	h := newHarness(t, nil)
	entered := make(chan struct{}, 1)
	var stops atomic.Int32
	h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp,
		activate:   func(ctx context.Context) error { entered <- struct{}{}; <-ctx.Done(); return ctx.Err() },
		deactivate: func(context.Context) error { stops.Add(1); return nil },
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h.setMode(control.ModeDrain)
	done := h.run(ctx)
	h.eventually("initial drain", func() bool { return h.m.Phase() == "idle" })
	h.setMode(control.ModeOn)
	<-entered
	h.eventually("starting phase", func() bool { return h.m.Phase() == "starting host runtimes" })
	for _, mode := range []control.Mode{control.ModeStop, control.ModeDrain} {
		h.setMode(mode)
		h.eventually("mode handled during activation", func() bool {
			s, _ := h.files.ReadStatus()
			return s != nil && s.Mode == mode && s.Phase == "idle"
		})
		if stops.Load() != 0 {
			t.Fatal("drain/stop deactivated runtime")
		}
	}
	h.setMode(control.ModeOff)
	if err := <-done; err != nil || stops.Load() != 1 {
		t.Fatal("off did not join activation and release", err, stops.Load())
	}
}

func TestRuntimeOffStatusOrderingAndFailure(t *testing.T) {
	h := newHarness(t, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp,
		activate: func(context.Context) error { return nil },
		deactivate: func(ctx context.Context) error {
			if _, ok := ctx.Deadline(); !ok {
				return errors.New("missing stop deadline")
			}
			close(entered)
			<-release
			return errors.New("guests remain; left running")
		},
	}
	h.setMode(control.ModeOff)
	done := h.run(t.Context())
	<-entered
	s, err := h.files.ReadStatus()
	if err != nil || s == nil || s.Phase != "releasing host runtimes" {
		t.Fatal("off reported completion before release", s, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal("deactivation failure prevented exit", err)
	}
	s, err = h.files.ReadStatus()
	if err != nil || s == nil || s.Phase != "exiting" || h.m.runtimeActive("macos") {
		t.Fatal("off did not finish release", s, err)
	}
}

func TestRuntimeDrainOnReactivates(t *testing.T) {
	h := newHarness(t, nil)
	var calls atomic.Int32
	h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp, activate: func(context.Context) error { calls.Add(1); return nil }}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h.setMode(control.ModeOn)
	done := h.run(ctx)
	h.eventually("polling", func() bool { return h.m.Phase() == "polling" })
	h.setMode(control.ModeDrain)
	h.eventually("drained", func() bool { return h.m.Phase() == "idle" })
	h.setMode(control.ModeOn)
	h.eventually("on again", func() bool { return h.m.Phase() == "polling" })
	if calls.Load() != 2 {
		t.Fatal("did not recheck runtime on entering On")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeOnTransitionRestartsManuallyStoppedHost(t *testing.T) {
	for _, mode := range []control.Mode{control.ModeDrain, control.ModeStop} {
		t.Run(string(mode), func(t *testing.T) {
			h := newHarness(t, nil)
			var serving atomic.Bool
			var calls atomic.Int32
			release := make(chan struct{})
			h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp, activate: func(ctx context.Context) error {
				if calls.Add(1) == 2 {
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				serving.Store(true)
				return nil
			}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			h.setMode(control.ModeOn)
			done := h.run(ctx)
			h.eventually("initial serving host", func() bool { return serving.Load() && h.m.Phase() == "polling" })
			h.setMode(mode)
			h.eventually("paused", func() bool { return h.m.Phase() == "idle" })
			serving.Store(false) // Simulate a manual stop while the manager stays up.
			h.setMode(control.ModeOn)
			h.eventually("revalidation", func() bool { return calls.Load() == 2 && h.m.Phase() == "starting host runtimes" })
			if h.m.runtimeActive("macos") || serving.Load() {
				t.Fatal("stopped runtime still offered capacity")
			}
			if _, err := h.m.launch(ctx, "macos", 1, false); err == nil {
				t.Fatal("launch bypassed revalidation")
			}
			close(release)
			h.eventually("host restarted", func() bool { return serving.Load() && h.m.Phase() == "polling" })
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRuntimeListFailureInvalidatesActiveProvider(t *testing.T) {
	for _, source := range []string{"status", "capacity", "reconcile"} {
		t.Run(source, func(t *testing.T) {
			h := newHarness(t, nil)
			var calls atomic.Int32
			var down atomic.Bool
			h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp,
				activate: func(context.Context) error { calls.Add(1); down.Store(false); return nil },
				list: func(ctx context.Context) ([]provider.Owned, []provider.Foreign, error) {
					if down.Load() {
						return nil, nil, errors.New("host stopped")
					}
					return h.fp.List(ctx)
				},
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer func() { cancel(); h.m.Wait() }()
			h.m.accepting.Store(true)
			h.m.activateAsync(ctx, time.Now())
			h.eventually("active", func() bool { return h.m.runtimeActive("macos") })
			down.Store(true)
			switch source {
			case "status":
				h.m.writeStatus(ctx, control.ModeOn)
			case "capacity":
				if capacity, _ := h.m.capacity(ctx, "macos"); capacity != 0 {
					t.Fatal("failed inventory offered capacity", capacity)
				}
			case "reconcile":
				if err := h.m.Reconcile(ctx); err != nil {
					t.Fatal("empty inactive provider aborted reconcile", err)
				}
			}
			if h.m.runtimeActive("macos") {
				t.Fatal("List failure left active sticky")
			}
			if _, err := h.m.launch(ctx, "macos", 1, true); err == nil {
				t.Fatal("launch ignored failed inventory")
			}
			h.m.activateAsync(ctx, time.Now())
			h.eventually("reactivated after List failure", func() bool { return calls.Load() == 2 && h.m.runtimeActive("macos") })
		})
	}
}

func TestRuntimeOnTransitionRechecksInFlightActivation(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.GitHub.Demand = config.DemandJIT })
	var calls atomic.Int32
	release := make(chan struct{})
	h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp, activate: func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}}
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); h.m.Wait() }()
	h.m.apply(ctx, control.ModeOn)
	h.eventually("activation in flight", func() bool { return calls.Load() == 1 })
	h.m.apply(ctx, control.ModeDrain)
	h.m.apply(ctx, control.ModeOn)
	if calls.Load() != 1 {
		t.Fatal("more than one activation in flight")
	}
	close(release)
	h.eventually("old worker joined", func() bool {
		h.m.mu.Lock()
		defer h.m.mu.Unlock()
		return !h.m.runtimes["macos"].activating
	})
	if h.m.runtimeActive("macos") {
		t.Fatal("old activation satisfied new On transition")
	}
	h.m.apply(ctx, control.ModeOn)
	h.eventually("new activation completed", func() bool { return calls.Load() == 2 && h.m.runtimeActive("macos") })
}

func TestRuntimeCancellationRacingOffJoinDoesNotDeactivate(t *testing.T) {
	h := newHarness(t, nil)
	entered, joining := make(chan struct{}), make(chan struct{})
	var stops atomic.Int32
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp,
		activate: func(c context.Context) error {
			close(entered)
			<-c.Done()
			// Off has cancelled the run context and is joining this worker.
			cancel()
			close(joining)
			return c.Err()
		},
		deactivate: func(context.Context) error { stops.Add(1); return nil },
	}
	h.setMode(control.ModeDrain)
	done := h.run(ctx)
	h.eventually("drain startup", func() bool { return h.m.Phase() == "idle" })
	h.setMode(control.ModeOn)
	<-entered
	h.setMode(control.ModeOff)
	<-joining
	if err := <-done; err != nil || stops.Load() != 0 {
		t.Fatal("signal racing Off deactivated runtime", err, stops.Load())
	}
}
