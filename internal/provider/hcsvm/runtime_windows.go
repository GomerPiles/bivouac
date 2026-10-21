//go:build windows

package hcsvm

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/GomerPiles/bivouac/internal/vmhost"
	"golang.org/x/sys/windows/svc"
)

// Service controls only the optional VM host service, with rights granted by
// its installer. State preserves pending transitions; Start/Stop wait for SCM.
type Service interface {
	State(ctx context.Context) (installed bool, state svc.State, err error)
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// CheckVMHost checks a serving host without starting a service or a guest.
// Doctor and activation share this method. Serving distinguishes an unavailable
// host (retryable during startup) from an incompatible one (fail immediately).
func (o Options) CheckVMHost(ctx context.Context, host Host) (serving bool, err error) {
	info, err := hostInfo(ctx, host)
	if err != nil {
		return false, fmt.Errorf("VM host unavailable (install the service with bivouac vmhost install, or run bivouac vmhost run elevated): %w", err)
	}
	return true, checkInfo(info, o.Image, o.CPU, o.MemoryMB)
}

func hostInfo(ctx context.Context, host Host) (vmhost.Info, error) {
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return host.Info(callCtx)
}

func checkInfo(info vmhost.Info, image string, cpu uint32, memoryMB uint64) error {
	if !slices.Contains(info.Images, image) {
		return fmt.Errorf("VM host has no image %q", image)
	}
	if cpu > info.MaxCPU || memoryMB > info.MaxMemoryMB {
		return errors.New("guest size exceeds the VM host's limits")
	}
	return nil
}

func (p *Provider) Activate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if serving, err := p.opts.CheckVMHost(ctx, p.host); serving {
		return err
	}
	if p.opts.Service == nil {
		return errors.New("VM host unavailable: install the service with bivouac vmhost install, or run bivouac vmhost run elevated")
	}
	for {
		installed, state, err := p.opts.Service.State(ctx)
		if err != nil {
			return fmt.Errorf("query VM host service: %w", err)
		}
		if !installed {
			return errors.New("VM host unavailable: install the service with bivouac vmhost install, or run bivouac vmhost run elevated")
		}
		switch state {
		case svc.Stopped:
			if err := p.opts.Service.Start(ctx); err != nil {
				return fmt.Errorf("start VM host service: %w", err)
			}
		case svc.StartPending, svc.StopPending:
			if err := waitRuntime(ctx); err != nil {
				return err
			}
			continue
		case svc.Running:
		default:
			return errors.New("VM host service is not running or starting; check bivouac vmhost status")
		}
		break
	}
	// SCM reports Running before startup recovery (up to two minutes) and
	// pipe readiness. Wait for the actual API within the caller's bound.
	for {
		// A serving but incompatible host must fail immediately, not retry.
		if serving, err := p.opts.CheckVMHost(ctx, p.host); serving {
			return err
		}
		if err := waitRuntime(ctx); err != nil {
			return fmt.Errorf("wait for VM host readiness: %w", err)
		}
	}
}

func waitRuntime(ctx context.Context) error {
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *Provider) Deactivate(ctx context.Context) error {
	if p.opts.Service == nil {
		return nil
	}
	installed, state, err := p.opts.Service.State(ctx)
	if err != nil {
		return fmt.Errorf("VM host left running: query service: %w", err)
	}
	if !installed || state == svc.Stopped {
		return nil
	}
	if state != svc.Running {
		return errors.New("VM host left running: service is transitioning or paused")
	}
	info, err := hostInfo(ctx, p.host)
	if err != nil {
		return fmt.Errorf("VM host left running: cannot prove it has no guests: %w", err)
	}
	if info.Running != 0 {
		return fmt.Errorf("VM host left running: %d guest reservations remain across all callers", info.Running)
	}
	// The check/stop window is accepted: configured accounts are bivouac's
	// own and this daemon is exiting. Running includes failed-cleanup reservations.
	if err := p.opts.Service.Stop(ctx); err != nil {
		return fmt.Errorf("VM host left running: stop service: %w", err)
	}
	return nil
}
