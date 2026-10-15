package manager

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

type probeFixture struct {
	provider.Provider
	status func(context.Context) (provider.RunnerStatus, error)
}

func (p probeFixture) RunnerStatus(ctx context.Context, _ string) (provider.RunnerStatus, error) {
	return p.status(ctx)
}

func probeHarness(t *testing.T) (*harness, *state.Instance) {
	t.Helper()
	h := newHarness(t, nil)
	h.m.o.RunnerStatusGrace = 100 * time.Millisecond
	h.m.o.RunnerStatusTimeout = 30 * time.Millisecond
	h.m.o.PollInterval = 5 * time.Millisecond
	i := &state.Instance{ID: "probe", Name: "bivouac-windows-probe", Provider: "macos", Phase: state.PhaseRunning, CreatedAt: time.Now()}
	if err := h.store.Put(i); err != nil {
		t.Fatal(err)
	}
	if err := h.fp.Create(context.Background(), provider.Spec{Name: i.Name, Meta: provider.Metadata{ControllerID: h.store.ControllerID(), InstanceID: i.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := h.fp.Start(context.Background(), i.Name, io.Discard); err != nil {
		t.Fatal(err)
	}
	return h, i
}

func TestTransientRunnerTransportRecoveryKeepsGuest(t *testing.T) {
	h, inst := probeHarness(t)
	var calls atomic.Int32
	p := probeFixture{Provider: h.fp, status: func(context.Context) (provider.RunnerStatus, error) {
		if calls.Add(1) <= 2 {
			return provider.RunnerStatus{}, fmt.Errorf("probe: %w", provider.SSHReset)
		}
		return provider.RunnerStatus{State: provider.RunnerRunning}, nil
	}}
	h.m.o.Providers[inst.Provider] = p
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.m.track(ctx, inst, true)
	h.eventually("recovered probe", func() bool { return calls.Load() >= 4 })
	if got, ok := h.store.Get(inst.ID); !ok || got.Phase != state.PhaseRunning || len(h.fp.Names()) != 1 {
		t.Fatal("transient status failure tore down the running guest")
	}
	cancel()
	h.m.Wait()
	if len(h.fp.Names()) != 1 {
		t.Fatal("controller cancellation deleted the guest")
	}
}

func TestPersistentRunnerTransportExpiresAndTearsDown(t *testing.T) {
	h, inst := probeHarness(t)
	var calls atomic.Int32
	h.m.o.Providers[inst.Provider] = probeFixture{Provider: h.fp, status: func(context.Context) (provider.RunnerStatus, error) {
		calls.Add(1)
		return provider.RunnerStatus{}, provider.SSHUnavailable
	}}
	started := time.Now()
	h.m.track(context.Background(), inst, true)
	h.m.Wait()
	if time.Since(started) < h.m.o.RunnerStatusGrace || calls.Load() < 2 {
		t.Fatal("transport failure retired guest before bounded grace")
	}
	if len(h.store.List()) != 0 || len(h.fp.Names()) != 0 {
		t.Fatal("persistent transport failure retained the guest indefinitely")
	}
}

func TestRunnerProbeTerminalErrorsAreImmediate(t *testing.T) {
	for _, failure := range []error{provider.ErrNotOwned, errors.New("native isolation failed"), provider.SSHHostKey, provider.SSHAuthentication, provider.SSHConfiguration, provider.SSHDiagnosticLimit, errors.New("invalid guest status"), errors.Join(provider.SSHReset, provider.ErrNotOwned)} {
		t.Run(failure.Error(), func(t *testing.T) {
			h, inst := probeHarness(t)
			calls := 0
			p := probeFixture{Provider: h.fp, status: func(context.Context) (provider.RunnerStatus, error) {
				calls++
				return provider.RunnerStatus{}, failure
			}}
			reason := h.m.waitRunner(context.Background(), &run{stopNow: make(chan struct{})}, p, inst)
			if calls != 1 || !strings.Contains(reason, failure.Error()) {
				t.Fatalf("terminal error retried: %d calls, %s", calls, reason)
			}
		})
	}
}

func TestRunnerProbeBoundsHungTransportAndHonorsStop(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(fmt.Sprint(stop), func(t *testing.T) {
			h, inst := probeHarness(t)
			r := &run{stopNow: make(chan struct{})}
			calls := 0
			p := probeFixture{Provider: h.fp, status: func(ctx context.Context) (provider.RunnerStatus, error) {
				calls++
				<-ctx.Done()
				if stop {
					close(r.stopNow)
				}
				return provider.RunnerStatus{}, provider.SSHTimeout
			}}
			started := time.Now()
			reason := h.m.waitRunner(context.Background(), r, p, inst)
			if stop {
				if reason != "stop requested" || calls != 1 {
					t.Fatal(reason, calls)
				}
			} else if !strings.Contains(reason, "grace expired") || calls < 2 {
				t.Fatal(reason, calls)
			}
			if time.Since(started) > time.Second {
				t.Fatal("probe exceeded bound")
			}
		})
	}
}

func TestRunnerProbeBudgetsAndCancellationDuringFailure(t *testing.T) {
	for _, mode := range []string{"job", "ready", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			h, inst := probeHarness(t)
			h.m.o.RunnerStatusGrace = time.Second
			p := probeFixture{Provider: h.fp, status: func(context.Context) (provider.RunnerStatus, error) {
				return provider.RunnerStatus{}, provider.SSHClosed
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "ready" {
				h.m.o.Config.Budget.ReadyTimeout.Duration = 25 * time.Millisecond
				if err := h.m.waitListening(ctx, p, inst); err == nil {
					t.Fatal("readiness waited beyond budget")
				}
				return
			}
			if mode == "job" {
				h.m.o.Config.Budget.JobTimeout.Duration = 25 * time.Millisecond
			} else {
				cancel()
			}
			reason := h.m.waitRunner(ctx, &run{stopNow: make(chan struct{})}, p, inst)
			if mode == "job" && reason != "job timeout" || mode == "cancel" && reason != reasonCancelled {
				t.Fatal(reason)
			}
		})
	}
}

func TestSuccessfulProbeResetsFailureWindowAndLogsRecovery(t *testing.T) {
	h, inst := probeHarness(t)
	var logs bytes.Buffer
	h.m.o.Log = slog.New(slog.NewTextHandler(&logs, nil))
	probe := runnerProbe{}
	failure := true
	p := probeFixture{Provider: h.fp, status: func(context.Context) (provider.RunnerStatus, error) {
		if failure {
			return provider.RunnerStatus{}, fmt.Errorf("synthetic-private-wrapper: %w", provider.SSHRefused)
		}
		return provider.RunnerStatus{State: provider.RunnerRunning}, nil
	}}
	deadline := time.Now().Add(time.Second)
	if _, delay, err := h.m.probeRunner(context.Background(), p, inst, deadline, &probe); err != nil || delay == 0 {
		t.Fatal(delay, err)
	}
	failure = false
	if _, delay, err := h.m.probeRunner(context.Background(), p, inst, deadline, &probe); err != nil || delay != 0 || !probe.since.IsZero() {
		t.Fatal(delay, err)
	}
	failure = true
	if _, delay, err := h.m.probeRunner(context.Background(), p, inst, deadline, &probe); err != nil || delay != h.m.o.PollInterval || probe.failures != 1 {
		t.Fatal(delay, err)
	}
	if !strings.Contains(logs.String(), "transport recovered") {
		t.Fatal("missing recovery log")
	}
	if strings.Contains(logs.String(), "synthetic-private") {
		t.Fatal("arbitrary wrapped error reached retry logs")
	}
}

func TestTransportRecoveryStillHonorsRunnerExitAndAbsence(t *testing.T) {
	for _, status := range []provider.RunnerState{provider.RunnerAbsent, provider.RunnerExited} {
		t.Run(string(status), func(t *testing.T) {
			h, inst := probeHarness(t)
			calls := 0
			p := probeFixture{Provider: h.fp, status: func(context.Context) (provider.RunnerStatus, error) {
				calls++
				if calls == 1 {
					return provider.RunnerStatus{}, provider.SSHClosed
				}
				return provider.RunnerStatus{State: status, ExitCode: 1}, nil
			}}
			reason := h.m.waitRunner(context.Background(), &run{stopNow: make(chan struct{})}, p, inst)
			if calls != 2 || reason != "runner process vanished" && reason != "runner exited 1" {
				t.Fatal(reason, calls)
			}
		})
	}
}
