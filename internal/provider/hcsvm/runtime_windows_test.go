//go:build windows

package hcsvm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/vmhost"
	"golang.org/x/sys/windows/svc"
)

type runtimeHost struct {
	Host
	info     vmhost.Info
	failures int
	calls    int
	err      error
}

func (h *runtimeHost) Info(context.Context) (vmhost.Info, error) {
	h.calls++
	if h.calls <= h.failures {
		return vmhost.Info{}, errors.New("pipe not ready")
	}
	return h.info, h.err
}

type fakeService struct {
	installed bool
	states    []svc.State
	queries   int
	starts    int
	stops     int
	err       error
	startErr  error
	stopErr   error
}

func (s *fakeService) State(context.Context) (bool, svc.State, error) {
	i := min(s.queries, len(s.states)-1)
	s.queries++
	if i < 0 {
		return s.installed, svc.Stopped, s.err
	}
	return s.installed, s.states[i], s.err
}
func (s *fakeService) Start(context.Context) error {
	s.starts++
	if s.startErr == nil && len(s.states) == 1 && s.states[0] == svc.Stopped {
		s.states[0] = svc.Running
	}
	return s.startErr
}
func (s *fakeService) Stop(context.Context) error { s.stops++; return s.stopErr }

func runtimeFixture(t *testing.T) (*Provider, *runtimeHost) {
	t.Helper()
	p, h, _ := fixture(t, true)
	rh := &runtimeHost{Host: h, info: vmhost.Info{Images: []string{p.opts.Image}, MaxCPU: p.opts.CPU, MaxMemoryMB: p.opts.MemoryMB}}
	p.host = rh
	return p, rh
}

func TestActivateServingHostDoesNotControlService(t *testing.T) {
	p, h := runtimeFixture(t)
	s := &fakeService{installed: true, states: []svc.State{svc.Stopped}}
	p.opts.Service = s
	if err := p.Activate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if s.queries != 0 || s.starts != 0 || h.calls != 1 {
		t.Fatal("serving foreground host touched service", s, h.calls)
	}
}

func TestActivateStartsAndWaitsForPipe(t *testing.T) {
	p, h := runtimeFixture(t)
	h.failures = 3
	s := &fakeService{installed: true, states: []svc.State{svc.Stopped}}
	p.opts.Service = s
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := p.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if s.starts != 1 || h.calls != 4 {
		t.Fatal("did not start and wait for recovery", s.starts, h.calls)
	}
}

func TestActivateWaitsForPendingServiceStates(t *testing.T) {
	for _, state := range []svc.State{svc.StartPending, svc.StopPending} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			p, h := runtimeFixture(t)
			h.failures = 1
			stable := svc.Running
			wantStarts := 0
			if state == svc.StopPending {
				stable = svc.Stopped
				wantStarts = 1
			}
			s := &fakeService{installed: true, states: []svc.State{state, stable}}
			p.opts.Service = s
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if err := p.Activate(ctx); err != nil || s.queries != 2 || s.starts != wantStarts {
				t.Fatal("pending service mishandled", err, s)
			}
		})
	}
}

func TestActivateMissingHostNamesBothRemedies(t *testing.T) {
	for _, service := range []Service{nil, &fakeService{}} {
		p, h := runtimeFixture(t)
		h.err = errors.New("down")
		p.opts.Service = service
		err := p.Activate(t.Context())
		if err == nil || !strings.Contains(err.Error(), "bivouac vmhost install") || !strings.Contains(err.Error(), "bivouac vmhost run elevated") {
			t.Fatal("missing remedies", err)
		}
	}
}

func TestRuntimeChecksImageAndLimits(t *testing.T) {
	for _, change := range []string{"image", "cpu", "memory"} {
		t.Run(change, func(t *testing.T) {
			p, h := runtimeFixture(t)
			switch change {
			case "image":
				h.info.Images = nil
			case "cpu":
				h.info.MaxCPU--
			case "memory":
				h.info.MaxMemoryMB--
			}
			if err := p.Activate(t.Context()); err == nil {
				t.Fatal("incompatible host activated")
			}
			if _, err := p.opts.CheckVMHost(t.Context(), h); err == nil {
				t.Fatal("doctor accepted incompatible host")
			}
			// The same validation must fail immediately after a service start.
			p.opts.Service = &fakeService{installed: true, states: []svc.State{svc.Stopped}}
			h.calls, h.failures = 0, 1
			if err := p.Activate(t.Context()); err == nil || h.calls != 2 {
				t.Fatal("incompatibility after start was retried", err, h.calls)
			}
		})
	}
}

func TestActivateCancellationAndServiceErrors(t *testing.T) {
	for _, stage := range []string{"query", "start", "pipe", "pending"} {
		t.Run(stage, func(t *testing.T) {
			p, h := runtimeFixture(t)
			cause := errors.New("down")
			h.err = cause
			s := &fakeService{installed: true, states: []svc.State{svc.Stopped}}
			failure := errors.New("service failure")
			switch stage {
			case "query":
				s.err = failure
			case "start":
				s.startErr = failure
			case "pending":
				s.states = []svc.State{svc.StopPending}
			}
			p.opts.Service = s
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
			defer cancel()
			err := p.Activate(ctx)
			if stage == "pipe" || stage == "pending" {
				failure = context.DeadlineExceeded
			}
			if !errors.Is(err, failure) {
				t.Fatal("lost activation error", err)
			}
			if (stage == "pipe" || stage == "pending") && !errors.Is(err, cause) {
				t.Fatal("activation timeout lost Info cause", err)
			}
		})
	}
}

func TestDeactivateGuards(t *testing.T) {
	for _, test := range []struct {
		name    string
		service *fakeService
		running int
		infoErr bool
		wantErr bool
		stops   int
	}{
		{name: "foreground"},
		{name: "not-installed", service: &fakeService{}},
		{name: "stopped", service: &fakeService{installed: true, states: []svc.State{svc.Stopped}}},
		{name: "other-callers-or-reservations", service: &fakeService{installed: true, states: []svc.State{svc.Running}}, running: 1, wantErr: true},
		{name: "unknown-guests", service: &fakeService{installed: true, states: []svc.State{svc.Running}}, infoErr: true, wantErr: true},
		{name: "empty", service: &fakeService{installed: true, states: []svc.State{svc.Running}}, stops: 1},
		{name: "pending", service: &fakeService{installed: true, states: []svc.State{svc.StartPending}}, wantErr: true},
		{name: "query-failed", service: &fakeService{err: errors.New("query failed")}, wantErr: true},
		{name: "stop-failed", service: &fakeService{installed: true, states: []svc.State{svc.Running}, stopErr: errors.New("stop failed")}, wantErr: true, stops: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, h := runtimeFixture(t)
			if test.service != nil {
				p.opts.Service = test.service
			}
			h.info.Running = test.running
			if test.infoErr {
				h.err = errors.New("pipe unavailable")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
			defer cancel()
			err := p.Deactivate(ctx)
			if (err != nil) != test.wantErr || (err != nil && !strings.Contains(err.Error(), "left running")) {
				t.Fatal("wrong release result", err)
			}
			if test.service != nil && test.service.stops != test.stops {
				t.Fatal("unsafe stop", test.service.stops)
			}
			if !test.wantErr && test.stops == 0 && h.calls != 0 {
				t.Fatal("foreground/no service should not need Info")
			}
		})
	}
}

func TestDeactivateWaitsForStartupRecovery(t *testing.T) {
	for _, running := range []int{0, 1} {
		t.Run(fmt.Sprint(running), func(t *testing.T) {
			p, h := runtimeFixture(t)
			h.failures = 2
			h.info.Running = running
			s := &fakeService{installed: true, states: []svc.State{svc.StartPending, svc.Running}}
			p.opts.Service = s
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			err := p.Deactivate(ctx)
			if running == 0 && (err != nil || s.stops != 1) {
				t.Fatal("idle host left running after startup", err, s.stops)
			}
			if running != 0 && (err == nil || s.stops != 0) {
				t.Fatal("guest guard bypassed after startup", err, s.stops)
			}
			if h.calls != 3 || s.starts != 0 {
				t.Fatal("release did not wait for Info", h.calls, s.starts)
			}
		})
	}
}

func TestDeactivateWaitsForStoppedService(t *testing.T) {
	for _, pending := range []svc.State{svc.StartPending, svc.StopPending, svc.Running} {
		t.Run(fmt.Sprint(pending), func(t *testing.T) {
			p, h := runtimeFixture(t)
			h.err = errors.New("pipe unavailable")
			s := &fakeService{installed: true, states: []svc.State{pending, svc.Stopped}}
			p.opts.Service = s
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if err := p.Deactivate(ctx); err != nil || s.stops != 0 || s.starts != 0 {
				t.Fatal("stopped service was not released", err, s)
			}
		})
	}
}

func TestRuntimeReadinessTimeoutKeepsLastCause(t *testing.T) {
	for _, action := range []string{"activate", "deactivate"} {
		t.Run(action, func(t *testing.T) {
			p, h := runtimeFixture(t)
			cause := errors.New("pipe access refused")
			h.err = cause
			s := &fakeService{installed: true, states: []svc.State{svc.Running}}
			p.opts.Service = s
			ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
			defer cancel()
			call := p.Activate
			if action == "deactivate" {
				call = p.Deactivate
			}
			err := call(ctx)
			if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cause) {
				t.Fatal("timeout lost its cause", err)
			}
			if s.stops != 0 {
				t.Fatal("unknown guest count stopped")
			}
		})
	}
}

func TestDeactivatePendingTimeoutKeepsLastState(t *testing.T) {
	p, h := runtimeFixture(t)
	s := &fakeService{installed: true, states: []svc.State{svc.StopPending}}
	p.opts.Service = s
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	err := p.Deactivate(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "transition pending") || s.stops != 0 || h.calls != 0 {
		t.Fatal("pending timeout lost its cause or bypassed guard", err)
	}
}

func TestActivateFailsWhenServiceStopsDuringReadiness(t *testing.T) {
	p, h := runtimeFixture(t)
	cause := errors.New("pipe not serving")
	h.err = cause
	s := &fakeService{installed: true, states: []svc.State{svc.Running, svc.Stopped}}
	p.opts.Service = s
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	err := p.Activate(ctx)
	if !errors.Is(err, cause) || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "service stopped") || s.starts != 0 {
		t.Fatal("service failure did not fail fast with cause", err)
	}
}

func TestCreateRejectsSpecResourceDisagreement(t *testing.T) {
	p, h, _ := fixture(t, true)
	for _, field := range []string{"image", "cpu", "memory"} {
		s := spec()
		s.Baseline, s.CPU, s.MemoryMB = p.opts.Image, 4, 8192
		switch field {
		case "image":
			s.Baseline = "other"
		case "cpu":
			s.CPU++
		case "memory":
			s.MemoryMB++
		}
		if err := p.Create(t.Context(), s); err == nil {
			t.Fatal("accepted conflicting spec", field)
		}
	}
	if len(h.creates) != 0 {
		t.Fatal("conflicting resource reservation reached VM host")
	}
	s := spec()
	s.Baseline, s.CPU, s.MemoryMB = p.opts.Image, 4, 8192
	if err := p.Create(t.Context(), s); err != nil {
		t.Fatal("matching reservation refused", err)
	}
	if h.creates[0].CPU != uint32(s.CPU) || h.creates[0].MemoryMB != uint64(s.MemoryMB) { // #nosec G115 -- fixture sizes are small positive constants.
		t.Fatal("request disagrees with reservation")
	}
}
