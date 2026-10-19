package vz

import "time"

// Startup records contain only fixed stage names, durations and outcomes. In
// particular, command arguments, errors, stdin and guest output never enter them.
func (p *Provider) startupStage(name, stage string, run func() error) error {
	started := time.Now()
	err := run()
	p.logStartup(name, stage, started, err)
	return err
}

func (p *Provider) logStartup(name, stage string, started time.Time, err error) {
	if p.log != nil {
		p.log.Info("startup stage", "provider", p.name, "name", name, "stage", stage,
			"duration_ms", time.Since(started).Milliseconds(), "success", err == nil)
	}
}
