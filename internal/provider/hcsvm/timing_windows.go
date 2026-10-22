//go:build windows

package hcsvm

import (
	"context"
	"log/slog"
	"sort"
	"time"
)

// All names originate in this package, never in guest replies or errors.
type timingStep string

const (
	stepSession           timingStep = "session"
	stepAgentDial         timingStep = "agent_dial"
	stepAgentInitialize   timingStep = "agent_initialize"
	stepSSHHandshake      timingStep = "ssh_handshake"
	stepNetwork           timingStep = "network"
	stepConfig            timingStep = "config"
	stepDeliveryPreflight timingStep = "delivery_preflight"
	stepDeliveryConfig    timingStep = "delivery_config"
	stepPreflight         timingStep = "preflight"
	stepConsoleProof      timingStep = "console_proof"
	stepDeliveryControl   timingStep = "delivery_control"
	stepDeliveryHelper    timingStep = "delivery_helper"
	stepDeliveryRunner    timingStep = "delivery_runner_archive"
	stepPrepare           timingStep = "prepare"
	stepDesktopProof      timingStep = "desktop_proof"
	stepClockSync         timingStep = "clock_sync"
	stepCacheSetup        timingStep = "cache_setup"
	stepJITDelivery       timingStep = "jit_delivery"
	stepRunnerStart       timingStep = "runner_start"
)

type instanceTiming struct {
	createStarted, createReturned time.Time
	jitStarted                    time.Time
}

// timingReport is also the lab's JSON payload. Numeric values are milliseconds,
// except agent_dial_retries. Missing fields mean the step was not reached.
type timingReport struct {
	SpansMS     map[string]int64 `json:"spans_ms"`
	FailureStep string           `json:"failure_step,omitempty"`
}

// timing owns a single synchronous operation's observations. It is not retained
// in a session and never holds command input, guest output or error text.
type timing struct {
	report  timingReport
	origin  time.Time
	started time.Time
	step    timingStep
	stepAt  time.Time
}

type timingContextKey struct{}

func newTiming(origin time.Time) *timing {
	return &timing{report: timingReport{SpansMS: make(map[string]int64)}, origin: origin, started: time.Now()}
}

func contextTiming(ctx context.Context) *timing {
	t, _ := ctx.Value(timingContextKey{}).(*timing)
	return t
}

func (t *timing) begin(step timingStep) {
	if t == nil {
		return
	}
	now := time.Now()
	t.end(now)
	t.step, t.stepAt = step, now
}

func (t *timing) end(now time.Time) {
	if t.step == "" {
		return
	}
	t.report.SpansMS[string(t.step)+"_ms"] = now.Sub(t.stepAt).Milliseconds()
	if !t.origin.IsZero() {
		t.report.SpansMS[string(t.step)+"_since_create_ms"] = now.Sub(t.origin).Milliseconds()
	}
}

func (t *timing) finish(total string, err error) timingReport {
	now := time.Now()
	t.end(now)
	t.report.SpansMS[total+"_ms"] = now.Sub(t.started).Milliseconds()
	if !t.origin.IsZero() {
		t.report.SpansMS[total+"_since_create_ms"] = now.Sub(t.origin).Milliseconds()
	}
	if err != nil {
		t.report.FailureStep = string(t.step)
	}
	return t.report
}

func (p *Provider) emitTiming(ctx context.Context, message string, report timingReport) {
	keys := make([]string, 0, len(report.SpansMS))
	for key := range report.SpansMS {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	attrs := make([]slog.Attr, 0, len(keys)+1)
	for _, key := range keys {
		attrs = append(attrs, slog.Int64(key, report.SpansMS[key]))
	}
	if report.FailureStep != "" {
		attrs = append(attrs, slog.String("failure_step", report.FailureStep))
	}
	p.logger.LogAttrs(ctx, slog.LevelInfo, message, attrs...)
}

func (p *Provider) observeListening(ctx context.Context, name string) {
	now := time.Now()
	p.mu.Lock()
	observed := p.timings[name]
	if observed.jitStarted.IsZero() {
		p.mu.Unlock()
		return
	}
	spans := map[string]int64{"jit_to_listening_ms": now.Sub(observed.jitStarted).Milliseconds()}
	if !observed.createStarted.IsZero() {
		spans["listening_since_create_ms"] = now.Sub(observed.createStarted).Milliseconds()
	}
	observed.jitStarted = time.Time{}
	p.timings[name] = observed
	p.mu.Unlock()
	p.emitTiming(ctx, "hcs listening timings", timingReport{SpansMS: spans})
}
