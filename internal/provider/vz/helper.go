package vz

import (
	"context"
	"errors"
	"os"
)

// installGuestHelper uploads one macOS executable shared by telemetry, caching
// and the optional container relay. The baseline agent is left untouched.
func (p *Provider) installGuestHelper(ctx context.Context, name string) error {
	p.mu.Lock()
	ready := p.helpers[name]
	p.mu.Unlock()
	if ready {
		return nil
	}
	err := p.startupStage(name, "helper_upload", func() error {
		exe, err := os.Executable()
		if local, ok := p.rt.(*local); ok {
			exe, err = local.exe, nil
		}
		if err != nil {
			return errors.New("locate guest helper source")
		}
		f, err := os.Open(exe)
		if err != nil {
			return errors.New("open guest helper source")
		}
		defer func() { _ = f.Close() }()
		// A stale symlink must never direct an upload/chmod into the agent.
		if _, err := p.output(ctx, name, []string{"rm", "-f", guestHelper}, nil); err != nil {
			return errors.New("prepare private guest helper path")
		}
		if _, err := p.output(ctx, name, []string{"/usr/bin/install", "-m", "0600", "/dev/null", guestHelper}, nil); err != nil {
			return errors.New("prepare guest helper")
		}
		if _, err := p.output(ctx, name, []string{"dd", "of=" + guestHelper, "status=none"}, f); err != nil {
			return errors.New("install guest helper")
		}
		_, err = p.output(ctx, name, []string{"chmod", "0700", guestHelper}, nil)
		return err
	})
	if err == nil {
		p.mu.Lock()
		p.helpers[name] = true
		p.mu.Unlock()
	}
	return err
}
