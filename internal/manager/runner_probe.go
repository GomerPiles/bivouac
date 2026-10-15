package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

// Each watcher owns its failure window; successful probes reset it. Neither
// stale status nor an unknown error is interpreted as a healthy runner.
type runnerProbe struct {
	since    time.Time
	failures int
	delay    time.Duration
	last     provider.TransportFailure
}

func (m *Manager) probeRunner(ctx context.Context, p provider.Provider, inst *state.Instance, deadline time.Time, probe *runnerProbe) (provider.RunnerStatus, time.Duration, error) {
	started := time.Now()
	if !probe.since.IsZero() {
		deadline = earlier(deadline, probe.since.Add(m.o.RunnerStatusGrace))
		if !started.Before(deadline) {
			return provider.RunnerStatus{}, 0, fmt.Errorf("runner transport failure grace expired after %d probes: %w", probe.failures, probe.last)
		}
	}
	probeCtx, cancel := context.WithDeadline(ctx, earlier(deadline, started.Add(m.o.RunnerStatusTimeout)))
	st, err := p.RunnerStatus(probeCtx, inst.Name)
	cancel()
	if ctx.Err() != nil {
		return provider.RunnerStatus{}, 0, ctx.Err()
	}
	if err == nil {
		if !probe.since.IsZero() {
			m.o.Log.Info("runner status transport recovered", "instance", inst.ID, "failures", probe.failures, "elapsed_ms", time.Since(probe.since).Milliseconds())
		}
		*probe = runnerProbe{}
		return st, 0, nil
	}
	var transport provider.TransportFailure
	if !errors.As(err, &transport) || !transport.Retryable() || errors.Is(err, provider.ErrNotOwned) || errors.Is(err, provider.ErrNotFound) {
		return provider.RunnerStatus{}, 0, err
	}
	probe.failures++
	probe.last = transport
	if probe.since.IsZero() {
		probe.since = started
		probe.delay = min(m.o.PollInterval, 10*time.Second)
		m.o.Log.Warn("runner status transport failed; retaining guest during grace", "instance", inst.ID, "class", transport.Error(), "grace_ms", m.o.RunnerStatusGrace.Milliseconds(), "probe_ms", time.Since(started).Milliseconds())
	} else {
		probe.delay = min(2*probe.delay, 10*time.Second)
	}
	remaining := time.Until(probe.since.Add(m.o.RunnerStatusGrace))
	if remaining <= 0 {
		return provider.RunnerStatus{}, 0, fmt.Errorf("runner transport failure grace expired after %d probes: %w", probe.failures, transport)
	}
	return provider.RunnerStatus{}, min(probe.delay, remaining), nil
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
