package vz

import (
	"context"
	"debug/elf"
	"errors"
	"runtime"

	"github.com/GomerPiles/bivouac/internal/macnetwork"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/rootnet"
	"github.com/GomerPiles/bivouac/internal/state"
)

// NetworkPolicy identifies the enforced transport. Destination policy is checked
// live by the rootless stack, rather than frozen into an old launch snapshot.
func NetworkPolicy() (string, error) { return rootnet.PolicyID, nil }

// CheckIsolation observes host policy availability without privileges, subprocess
// probes or VM launch. The helper must successfully create its own rootless stack.
func CheckIsolation(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return errors.New("isolated runners require Apple Silicon macOS")
	}
	_, err := macnetwork.Policy()
	return err
}

func (p *Provider) preflightEngine(ctx context.Context) error {
	if p.cfg.Containers == nil {
		return nil
	}
	if p.runner.OS != "darwin" {
		return errors.New("container pairs require a Darwin runner")
	}
	for _, b := range []struct{ name, os string }{{p.cfg.Baseline, p.runner.OS}, {p.cfg.Containers.Baseline, "linux"}} {
		var err error
		if b.os == "linux" {
			_, err = CheckLinuxBaseline(string(p.store), b.name, p.cfg.Containers.Helper, "")
		} else {
			_, err = CheckBaseline(string(p.store), b.name, b.os)
		}
		if err != nil {
			return err
		}
	}
	f, err := elf.Open(p.cfg.Containers.Helper)
	if err != nil {
		return errors.New("containers.helper must be a built Linux/arm64 bivouac binary")
	}
	defer func() { _ = f.Close() }()
	if f.Machine != elf.EM_AARCH64 || f.Class != elf.ELFCLASS64 {
		return errors.New("container helper architecture mismatch")
	}
	err = p.isolation(ctx)
	return err
}

// CheckContainers is the read-only doctor/pre-admission check. It never boots
// a baseline, opens a container daemon, or changes privilege configuration.
func (p *Provider) CheckContainers(ctx context.Context) error { return p.preflightEngine(ctx) }
func (p *Provider) isolation(ctx context.Context) error {
	if p.checkIsolation != nil {
		return p.checkIsolation(ctx)
	}
	return CheckIsolation(ctx)
}

// runnerIsolation is repeated before private bootstrap/JIT and on adoption.
// Cleanup deliberately uses raw ownership/status, so an obsolete NAT guest can
// still be retired without claiming that it satisfies the new policy.
func (p *Provider) runnerIsolation(name string) error {
	if err := p.ownsGuest(name); err != nil {
		return err
	}
	m, _ := p.readMeta(name)
	if _, local := p.rt.(*local); local || p.runner.OS == "linux" {
		if p.records == nil {
			return provider.ErrNotOwned
		}
		found := false
		for _, i := range p.records.List() {
			if i.Name == name && i.ID == m.InstanceID && i.Provider == p.name && (p.runner.OS != "linux" || i.EngineName == "") && i.Phase != state.PhaseDeregistering && p.records.ControllerID() == m.ControllerID {
				found = true
				break
			}
		}
		if !found {
			return provider.ErrNotOwned
		}
	}
	policy, err := NetworkPolicy()
	if err != nil || m.NetworkPolicy != policy {
		return errors.New("guest network policy differs; drain and replace the guest")
	}
	if proof, ok := p.rt.(interface{ ProveIsolation(string, string) error }); ok {
		return proof.ProveIsolation(name, policy)
	}
	return errors.New("runtime cannot prove network isolation")
}

func (p *Provider) preflightRunner(ctx context.Context) error {
	m, err := CheckRunnerBaseline(string(p.store), p.cfg.Baseline, p.name, p.runner)
	if err != nil {
		return err
	}
	if err := MachineOptions(p.cfg.Machine).CheckGuest(m); err != nil {
		return err
	}
	if err := p.runner.CheckHelper(); err != nil {
		return err
	}
	return p.isolation(ctx)
}
