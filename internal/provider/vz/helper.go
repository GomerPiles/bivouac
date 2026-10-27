package vz

import (
	"context"
	"errors"
	"os"

	"github.com/GomerPiles/bivouac/internal/vm"
)

// installGuestHelper uploads one executable selected for the clone OS, shared
// by telemetry, caching and the optional container relay. The baseline agent is left untouched.
func (p *Provider) installGuestHelper(ctx context.Context, name string) error {
	p.mu.Lock()
	ready := p.helpers[name]
	p.mu.Unlock()
	if ready {
		return nil
	}
	err := p.startupStage(name, "helper_upload", func() error {
		exe, destination, err := p.guestHelperSource(name)
		if err != nil {
			return err
		}
		f, err := os.Open(exe)
		if err != nil {
			return errors.New("open guest helper source")
		}
		defer func() { _ = f.Close() }()
		// A stale symlink must never direct an upload/chmod into the agent.
		if _, err := p.output(ctx, name, []string{"rm", "-f", destination}, nil); err != nil {
			return errors.New("prepare private guest helper path")
		}
		if _, err := p.output(ctx, name, []string{"/usr/bin/install", "-m", "0600", "/dev/null", destination}, nil); err != nil {
			return errors.New("prepare guest helper")
		}
		if _, err := p.output(ctx, name, []string{"dd", "of=" + destination, "status=none"}, f); err != nil {
			return errors.New("install guest helper")
		}
		_, err = p.output(ctx, name, []string{"chmod", "0700", destination}, nil)
		return err
	})
	if err == nil {
		p.mu.Lock()
		p.helpers[name] = true
		p.mu.Unlock()
	}
	return err
}

// Source selection consults only the retained clone and the selected executable,
// never a baseline. Guest preparation is admission work, not adoption/status.
func (p *Provider) guestHelperSource(name string) (source, destination string, err error) {
	m, err := vm.ReadManifest(p.vmDir(name))
	if err != nil {
		return "", "", err
	}
	switch m.OS {
	case "darwin":
		exe, err := os.Executable()
		if local, ok := p.rt.(*local); ok {
			exe, err = local.exe, nil
		}
		if err != nil {
			return "", "", errors.New("locate guest helper source")
		}
		return exe, guestHelper, nil
	case "linux":
		if p.runner.OS != m.OS {
			return "", "", errors.New("guest helper OS selection differs")
		}
		if err := p.runner.CheckHelper(); err != nil {
			return "", "", err
		}
		// The neutral runtime requires this fixed basename before preparation.
		return p.runner.Helper, guestPath, nil
	default:
		return "", "", errors.New("unsupported VZ guest helper OS")
	}
}
