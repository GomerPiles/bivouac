package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/provider"
)

const (
	runtimeTimeout = 3 * time.Minute
	runtimeRetry   = 30 * time.Second
)

type runtimeState struct {
	active     bool
	activating bool
	retry      time.Time
}

// ActivationError is a startup failure requiring an available host runtime.
// The CLI reports it through the daemon's startup-failure status path.
type ActivationError struct {
	Provider string
	Err      error
}

func (e *ActivationError) Error() string {
	return fmt.Sprintf("activate provider %s: %v", e.Provider, e.Err)
}

func (e *ActivationError) Unwrap() error { return e.Err }

func (m *Manager) runtimeActive(name string) bool {
	if _, ok := m.o.Providers[name].(provider.Activator); !ok {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runtimes[name].active
}

// Startup needs inventory for On or retained records. Fail before reconciliation
// rather than treating an unavailable runtime as proof that its guests are gone.
func (m *Manager) activateStartup(ctx context.Context, mode control.Mode) error {
	for name, p := range m.o.Providers {
		a, ok := p.(provider.Activator)
		if !ok || (mode != control.ModeOn && len(m.activeFor(name)) == 0) {
			continue
		}
		m.setPhase("starting host runtimes")
		m.writeStatus(ctx, mode)
		if err := bounded(ctx, runtimeTimeout, a.Activate); err != nil {
			return &ActivationError{Provider: name, Err: err}
		}
		m.mu.Lock()
		m.runtimes[name] = runtimeState{active: true}
		m.mu.Unlock()
	}
	return nil
}

// activateAsync runs only on the control loop. Each worker is joined with the
// instance lifecycles and cancelled through Run's context, never a poller's.
// Inactive providers keep On in its starting phase even during retry backoff.
func (m *Manager) activateAsync(ctx context.Context, now time.Time) bool {
	starting := false
	for name, p := range m.o.Providers {
		a, ok := p.(provider.Activator)
		if !ok {
			continue
		}
		m.mu.Lock()
		r := m.runtimes[name]
		if r.active {
			m.mu.Unlock()
			continue
		}
		starting = true
		if r.activating || now.Before(r.retry) || ctx.Err() != nil {
			m.mu.Unlock()
			continue
		}
		r.activating = true
		m.runtimes[name] = r
		m.wg.Add(1)
		m.mu.Unlock()
		go func() {
			defer m.wg.Done()
			err := bounded(ctx, runtimeTimeout, a.Activate)
			m.mu.Lock()
			r := runtimeState{active: err == nil}
			if err != nil {
				r.retry = time.Now().Add(runtimeRetry)
			}
			m.runtimes[name] = r
			m.mu.Unlock()
			if err != nil {
				m.o.Log.Warn("activate host runtime", "provider", name, "error", err)
			}
			m.notify()
		}()
	}
	return starting
}

func (m *Manager) deactivate(ctx context.Context) {
	for name, p := range m.o.Providers {
		a, ok := p.(provider.Activator)
		if !ok {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		// Include providers this daemon never activated: a prior daemon may
		// have crashed. Only the provider can prove it is safe to stop.
		if err := bounded(ctx, runtimeTimeout, a.Deactivate); err != nil {
			m.o.Log.Warn("deactivate host runtime; left running", "provider", name, "error", err)
		}
		m.mu.Lock()
		m.runtimes[name] = runtimeState{}
		m.mu.Unlock()
	}
}
