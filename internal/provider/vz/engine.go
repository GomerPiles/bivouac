package vz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/engine"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

// SetRecords binds engine operations to the durable per-job ownership record.
func (p *Provider) SetRecords(records *state.Store) { p.records = records }

func (p *Provider) pairRecord(name string) (*state.Instance, error) {
	if p.records == nil || p.cfg.Containers == nil {
		return nil, provider.ErrNotOwned
	}
	for _, i := range p.records.List() {
		if i.Name == name && i.Provider == p.name && i.EngineName == name+"-engine" && i.ContainerEngine == p.cfg.Containers.Engine && i.ID != "" && p.records.ControllerID() == p.controllerID {
			return i, nil
		}
	}
	return nil, provider.ErrNotOwned
}

func (p *Provider) pairStatus(ctx context.Context, name string) (provider.Status, provider.Status, error) {
	i, err := p.pairRecord(name)
	if err != nil {
		return provider.Status{}, provider.Status{}, err
	}
	a, err := p.statusVM(ctx, name)
	if err != nil {
		return a, provider.Status{}, err
	}
	b, err := p.statusVM(ctx, i.EngineName)
	if err != nil {
		return a, b, err
	}
	a.Owned = a.Owned && a.Meta.InstanceID == i.ID && a.Meta.EngineName == i.EngineName && a.Meta.ParentName == ""
	b.Owned = b.Owned && b.Meta.InstanceID == i.ID && b.Meta.ParentName == name && b.Meta.EngineName == ""
	return a, b, nil
}

// Create persists pair linkage in both provider markers. The manager has already
// recorded both names. Any failure retains the record for ownership-checked retry.
func (p *Provider) Create(ctx context.Context, spec provider.Spec) error {
	if p.cfg.Containers == nil {
		return p.createVM(ctx, spec)
	}
	i, err := p.pairRecord(spec.Name)
	if err != nil {
		return err
	}
	if spec.Meta.InstanceID != i.ID || spec.Meta.ControllerID != p.controllerID {
		return provider.ErrNotOwned
	}
	if err = p.preflightEngine(ctx); err != nil {
		return err
	}
	for _, n := range []string{spec.Name, i.EngineName} {
		st, err := p.statusVM(ctx, n)
		if err != nil {
			return err
		}
		if st.Exists {
			return provider.ErrNotOwned
		}
	}
	spec.Meta.EngineName = i.EngineName
	if err = p.createVM(ctx, spec); err != nil {
		return err
	}
	meta := spec.Meta
	meta.EngineName = ""
	meta.ParentName = spec.Name
	e := p.cfg.Containers
	return p.createVM(ctx, provider.Spec{Name: i.EngineName, Baseline: e.Baseline, CPU: e.CPU, MemoryMB: e.MemoryGB * 1024, Meta: meta})
}

func (p *Provider) Start(ctx context.Context, name string, log io.Writer) error {
	if p.cfg.Containers == nil {
		return p.startVM(ctx, name, p.runnerLaunch(), log)
	}
	a, b, err := p.pairStatus(ctx, name)
	if err != nil {
		return err
	}
	if !a.Exists || !b.Exists || !a.Owned || !b.Owned {
		return provider.ErrNotOwned
	}
	softnet, err := p.isolation(ctx)
	if err != nil {
		return err
	}
	policy := softnet.Block
	// Save the effective policy for adoption; it is not allowed to change on a
	// live job. Both markers remain until their respective VM is deleted.
	for _, n := range []string{name, name + "-engine"} {
		m, _ := p.readMeta(n)
		m.NetworkPolicy = policy
		data, err := json.Marshal(m)
		if err != nil {
			return err
		}
		if err = state.WriteAtomic(filepath.Join(p.vmDir(n), markerFile), data, 0o600); err != nil {
			return err
		}
	}
	// Isolated guests get Softnet, no input devices, and no shares.
	if err = p.startVM(ctx, name+"-engine", Launch{Softnet: &softnet}, log); err != nil {
		return err
	}
	return p.startVM(ctx, name, Launch{Softnet: &softnet}, log)
}

func (p *Provider) WaitReady(ctx context.Context, name string) error {
	if p.cfg.Containers != nil {
		a, b, err := p.pairStatus(ctx, name)
		if err != nil {
			return err
		}
		if !a.Exists || !b.Exists || !a.Owned || !b.Owned {
			return provider.ErrNotOwned
		}
	}
	if err := p.ownsGuest(name); err != nil {
		return err
	}
	if err := p.waitVM(ctx, name); err != nil {
		return err
	}
	if err := p.installGuestScript(ctx, name); err != nil {
		return err
	}
	if err := p.checkSession(ctx, name); err != nil {
		return err
	}
	if p.cfg.Containers == nil {
		return nil
	}
	a, b, err := p.pairStatus(ctx, name)
	if err != nil || !a.Owned || !b.Owned {
		return provider.ErrNotOwned
	}
	if err = p.waitVM(ctx, name+"-engine"); err != nil {
		return err
	}
	for _, f := range []struct{ name, path string }{{name, ""}, {name + "-engine", p.cfg.Containers.Helper}} {
		path := f.path
		if path == "" {
			path, err = os.Executable()
			if err != nil {
				return err
			}
		}
		file, err := os.Open(path)
		if err != nil {
			return errors.New("open container guest helper")
		}
		_, err = p.output(ctx, f.name, []string{"install", "-m", "0600", "/dev/null", engine.GuestHelper}, nil)
		if err == nil {
			_, err = p.output(ctx, f.name, []string{"dd", "of=" + engine.GuestHelper, "status=none"}, file)
		}
		_ = file.Close()
		if err != nil {
			return errors.New("deliver private container helper")
		}
		if _, err = p.output(ctx, f.name, []string{"chmod", "0700", engine.GuestHelper}, nil); err != nil {
			return err
		}
		if _, err = p.output(ctx, f.name, []string{engine.GuestHelper, "engine", "dns"}, nil); err != nil {
			return errors.New("configure public guest DNS")
		}
	}
	// Verify a matching CLI exists in the runner baseline. Never install tools.
	if _, err = p.output(ctx, name, []string{p.cfg.Containers.Engine, "--version"}, nil); err != nil {
		return errors.New("container CLI missing from macOS baseline")
	}
	i, err := p.pairRecord(name)
	if err != nil {
		return err
	}
	plan := RelayPlan{StatePath: p.records.Path(), Store: string(p.store), Name: name, InstanceID: i.ID, ControllerID: p.controllerID, Engine: p.cfg.Containers.Engine, Policy: a.Meta.NetworkPolicy}
	start := p.startRelay
	if start == nil {
		start = startDetachedRelay
	}
	proc, err := start(context.WithoutCancel(ctx), plan)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.procs[name+":relay"] = proc
	p.mu.Unlock()
	for {
		select {
		case <-proc.Done():
			return errors.New("container relay exited before ready")
		default:
		}
		if err = p.engineHealthy(ctx, name); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (p *Provider) engineHealthy(ctx context.Context, name string) error {
	a, b, err := p.pairStatus(ctx, name)
	if err != nil {
		return err
	}
	if !a.Exists || !b.Exists || !a.Owned || !b.Owned || !a.Running || !b.Running {
		return errors.New("container pair unavailable")
	}
	policy, err := NetworkPolicy()
	if err != nil || policy != a.Meta.NetworkPolicy || policy != b.Meta.NetworkPolicy {
		return errors.New("host network changed; container pair must be retired")
	}
	if relay, ok := p.proc(name + ":relay"); ok {
		select {
		case <-relay.Done():
			return errors.New("container relay exited")
		default:
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	_, err = p.output(ctx, name, []string{engine.GuestHelper, "engine", "probe"}, nil)
	if err != nil {
		// Both VMs run, are owned, and the policy holds: a failed probe is a
		// guest agent transport failure. The relay retires the pair itself on
		// a lasting loss.
		return fmt.Errorf("container relay probe unavailable: %w", provider.GuestAgentUnavailable)
	}
	return nil
}

func (p *Provider) Status(ctx context.Context, name string) (provider.Status, error) {
	if p.cfg.Containers == nil {
		return p.statusVM(ctx, name)
	}
	a, b, err := p.pairStatus(ctx, name)
	if err != nil {
		return provider.Status{}, err
	}
	st := a
	st.Exists = a.Exists || b.Exists
	st.Running = a.Running || b.Running
	st.Owned = (!a.Exists || a.Owned) && (!b.Exists || b.Owned)
	return st, nil
}

func (p *Provider) Stop(ctx context.Context, name string, timeout time.Duration) error {
	if p.cfg.Containers == nil {
		if m, ok := p.readMeta(name); ok && (m.ParentName != "" || m.EngineName != "") {
			return provider.ErrNotOwned
		}
		return p.stopVM(ctx, name, timeout)
	}
	a, b, err := p.pairStatus(ctx, name)
	if err != nil {
		return err
	}
	if (a.Exists && !a.Owned) || (b.Exists && !b.Owned) {
		return provider.ErrNotOwned
	}
	if proc, ok := p.proc(name + ":relay"); ok {
		_ = proc.Kill()
	}
	var errs []error
	if a.Exists && a.Running {
		errs = append(errs, p.stopVM(ctx, name, timeout))
	}
	if b.Exists && b.Running {
		errs = append(errs, p.stopVM(ctx, name+"-engine", timeout))
	}
	return errors.Join(errs...)
}

func (p *Provider) Delete(ctx context.Context, name string) error {
	if p.cfg.Containers == nil {
		if m, ok := p.readMeta(name); ok && (m.ParentName != "" || m.EngineName != "") {
			return provider.ErrNotOwned
		}
		return p.deleteVM(ctx, name)
	}
	a, b, err := p.pairStatus(ctx, name)
	if err != nil {
		return err
	}
	if (a.Exists && !a.Owned) || (b.Exists && !b.Owned) {
		return provider.ErrNotOwned
	}
	if a.Running || b.Running {
		return errors.New("refusing to delete a running container pair")
	}
	var errs []error
	// Delete engine first. If either delete fails, the composite Status keeps the
	// manager's reservation until both absences are confirmed.
	for _, n := range []string{name + "-engine", name} {
		if err := p.deleteVM(ctx, n); err != nil && !errors.Is(err, provider.ErrNotFound) {
			errs = append(errs, err)
		}
	}
	if err = errors.Join(errs...); err != nil {
		return err
	}
	st, err := p.Status(ctx, name)
	if err != nil {
		return err
	}
	if st.Exists {
		return errors.New("container pair deletion not confirmed")
	}
	p.forget(name + ":relay")
	if !a.Exists && !b.Exists {
		return provider.ErrNotFound
	}
	return nil
}

func (p *Provider) List(ctx context.Context) ([]provider.Owned, []provider.Foreign, error) {
	if p.cfg.Containers == nil {
		owned, foreign, err := p.listVMs(ctx)
		if err != nil {
			return nil, nil, err
		}
		var safe []provider.Owned
		for _, o := range owned {
			if o.Meta.ParentName != "" || o.Meta.EngineName != "" {
				foreign = append(foreign, provider.Foreign{Name: o.Name, Running: o.Running, Prefixed: true})
			} else {
				safe = append(safe, o)
			}
		}
		return safe, foreign, nil
	}
	entries, err := p.list(ctx)
	if err != nil {
		return nil, nil, err
	}
	known := make(map[string]bool)
	var owned []provider.Owned
	if p.records != nil {
		for _, i := range p.records.List() {
			if i.Provider != p.name || i.EngineName == "" {
				continue
			}
			known[i.Name], known[i.EngineName] = true, true
			a, b, err := p.pairStatus(ctx, i.Name)
			if err != nil {
				return nil, nil, err
			}
			if (!a.Exists || a.Owned) && (!b.Exists || b.Owned) && (a.Exists || b.Exists) {
				owned = append(owned, provider.Owned{Name: i.Name, Running: a.Running || b.Running, Meta: a.Meta})
			} else {
				known[i.Name], known[i.EngineName] = false, false
			}
		}
	}
	var foreign []provider.Foreign
	for _, e := range entries {
		if known[e.Name] {
			continue
		}
		prefixed := strings.HasPrefix(e.Name, "bivouac-")
		if e.Running || prefixed {
			foreign = append(foreign, provider.Foreign{Name: e.Name, Running: e.Running, Prefixed: prefixed})
		}
	}
	return owned, foreign, nil
}

// startDetachedRelay survives a controller crash. It has no host listener and
// exits when either guest disappears; guest stdout/stderr never reach host logs.
func startDetachedRelay(ctx context.Context, plan RelayPlan) (Process, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	return (CLI{Binary: exe}).startInput(ctx, []string{"engine", "relay"}, bytes.NewReader(data), io.Discard)
}
