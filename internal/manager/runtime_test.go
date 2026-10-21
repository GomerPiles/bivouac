package manager

import (
	"context"
	"errors"
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

func TestRuntimeStartupBeforeReconcileAndLaunch(t *testing.T) {
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
			if mode != control.ModeOn {
				if err := h.store.Put(&state.Instance{ID: "retained", Provider: "macos", Name: "bivouac-macos-retained", Phase: state.PhaseRunning, ScaleSetID: 1}); err != nil {
					t.Fatal(err)
				}
			}
			failure := errors.New("activation failed")
			h.m.o.Providers["macos"] = &runtimeProvider{Provider: h.fp, activate: func(context.Context) error { return failure }}
			h.setMode(mode)
			err := h.m.Run(t.Context())
			var activationErr *ActivationError
			if !errors.Is(err, failure) || !errors.As(err, &activationErr) {
				t.Fatal("startup did not fail", err)
			}
			if mode != control.ModeOn && len(h.store.List()) != 1 {
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
	if _, err := h.m.launch(ctx, "macos", 1, true); err != nil {
		t.Fatal("activated provider blocked", err)
	}
	if calls.Load() != 2 {
		t.Fatal("wrong retry count")
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

func TestRuntimeDrainOnDoesNotReactivate(t *testing.T) {
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
	if calls.Load() != 1 {
		t.Fatal("reactivated active runtime")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
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
