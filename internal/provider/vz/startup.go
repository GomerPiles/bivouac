package vz

import (
	"log/slog"
	"time"
)

// SetLogger attaches the daemon's redacted sink before any lifecycle work.
func (p *Provider) SetLogger(log *slog.Logger) { p.log = log }

// Startup records contain only fixed stage names, durations and outcomes. In
// particular, command arguments, errors, stdin and guest output never enter them.
func (p *Provider) startupStage(name, stage string, run func() error) error {
	started := time.Now()
	err := run()
	p.logStartup(name, stage, started, err)
	return err
}

func (p *Provider) logStartup(name, stage string, started time.Time, err error, attrs ...any) {
	if p.log != nil {
		fields := []any{"provider", p.name, "name", name, "stage", stage,
			"duration_ms", time.Since(started).Milliseconds(), "success", err == nil}
		p.log.Info("macos startup stage", append(fields, attrs...)...)
	}
}
