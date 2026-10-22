// Package fake is an in-memory provider for lifecycle tests. It records every
// call and lets tests drive readiness, runner exit, and failures.
package fake

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/provider"
)

// Instance is the fake's record of one guest.
type Instance struct {
	Spec     provider.Spec
	Running  bool
	Runner   provider.RunnerStatus
	JIT      []byte
	ready    chan struct{}
	exited   chan struct{}
	exitCode int
}

// Provider is the fake engine.
type Provider struct {
	name string
	caps provider.Capabilities

	mu        sync.Mutex
	instances map[string]*Instance
	preReady  map[string]bool // MarkReady called before Create
	foreign   []provider.Foreign
	Calls     []string
	// FailCreate, FailStart, FailRunner make the next matching call fail.
	FailCreate, FailStart, FailRunner error
	// HangDiagnostics makes CollectDiagnostics block until its context ends,
	// like a guest that never closes its diagnostics stream.
	HangDiagnostics bool
	// ControllerID is what Delete expects in metadata.
	ControllerID string
}

// New returns a fake provider that reports a desktop session.
func New(name, controllerID string) *Provider {
	return &Provider{
		name:         name,
		caps:         provider.Capabilities{GPU: provider.GPUParavirtualized, DesktopSession: true, DisplayTransport: "none", HostLimit: 2},
		instances:    map[string]*Instance{},
		preReady:     map[string]bool{},
		ControllerID: controllerID,
	}
}

func (p *Provider) record(format string, args ...any) {
	p.Calls = append(p.Calls, fmt.Sprintf(format, args...))
}

// Name implements provider.Provider.
func (p *Provider) Name() string { return p.name }

// Capabilities implements provider.Provider.
func (p *Provider) Capabilities() provider.Capabilities { return p.caps }

// AddForeign makes a running guest bivouac does not own appear in List. A
// name with the bivouac prefix is reported as prefixed, like an unprovable
// record of Crosvm.
func (p *Provider) AddForeign(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.foreign = append(p.foreign, provider.Foreign{Name: name, Running: true, Prefixed: strings.HasPrefix(name, "bivouac-")})
}

// AddUnowned plants a stopped guest with foreign metadata, to prove cleanup
// refuses it.
func (p *Provider) AddUnowned(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.instances[name] = &Instance{Spec: provider.Spec{Name: name, Meta: provider.Metadata{ControllerID: "someone-else"}}, ready: make(chan struct{}), exited: make(chan struct{})}
}

// Create implements provider.Provider.
func (p *Provider) Create(_ context.Context, spec provider.Spec) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record("create %s from %s", spec.Name, spec.Baseline)
	if p.FailCreate != nil {
		err := p.FailCreate
		p.FailCreate = nil
		return err
	}
	if _, ok := p.instances[spec.Name]; ok {
		return fmt.Errorf("fake: %s exists", spec.Name)
	}
	inst := &Instance{Spec: spec, ready: make(chan struct{}), exited: make(chan struct{}), Runner: provider.RunnerStatus{State: provider.RunnerAbsent}}
	if p.preReady[spec.Name] {
		close(inst.ready)
		delete(p.preReady, spec.Name)
	}
	p.instances[spec.Name] = inst
	return nil
}

// Start implements provider.Provider.
func (p *Provider) Start(_ context.Context, name string, launchLog io.Writer) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record("start %s", name)
	if p.FailStart != nil {
		err := p.FailStart
		p.FailStart = nil
		return err
	}
	inst, ok := p.instances[name]
	if !ok {
		return provider.ErrNotFound
	}
	inst.Running = true
	_, _ = fmt.Fprintf(launchLog, "fake launch %v\n", inst.Spec.Launch.Args)
	return nil
}

// WaitReady implements provider.Provider.
func (p *Provider) WaitReady(ctx context.Context, name string) error {
	p.mu.Lock()
	inst, ok := p.instances[name]
	p.mu.Unlock()
	if !ok {
		return provider.ErrNotFound
	}
	select {
	case <-inst.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// StartRunner implements provider.Provider.
func (p *Provider) StartRunner(_ context.Context, name string, jit []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record("runner %s", name)
	if p.FailRunner != nil {
		err := p.FailRunner
		p.FailRunner = nil
		return err
	}
	inst, ok := p.instances[name]
	if !ok {
		return provider.ErrNotFound
	}
	inst.JIT = append([]byte(nil), jit...)
	inst.Runner = provider.RunnerStatus{State: provider.RunnerListening}
	return nil
}

// StopRunner implements provider.Provider.
func (p *Provider) StopRunner(_ context.Context, name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record("stop-runner %s", name)
	inst, ok := p.instances[name]
	if !ok {
		return provider.ErrNotFound
	}
	if inst.Spec.Meta.ControllerID != p.ControllerID {
		return provider.ErrNotOwned
	}
	inst.Runner = provider.RunnerStatus{State: provider.RunnerExited}
	return nil
}

// RunnerStatus implements provider.Provider.
func (p *Provider) RunnerStatus(_ context.Context, name string) (provider.RunnerStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	inst, ok := p.instances[name]
	if !ok {
		return provider.RunnerStatus{}, provider.ErrNotFound
	}
	return inst.Runner, nil
}

// Status implements provider.Provider.
func (p *Provider) Status(_ context.Context, name string) (provider.Status, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	inst, ok := p.instances[name]
	if !ok {
		return provider.Status{}, nil
	}
	return provider.Status{Exists: true, Running: inst.Running, Owned: inst.Spec.Meta.ControllerID == p.ControllerID, Meta: inst.Spec.Meta}, nil
}

// Stop implements provider.Provider.
func (p *Provider) Stop(_ context.Context, name string, _ time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record("stop %s", name)
	inst, ok := p.instances[name]
	if !ok {
		return provider.ErrNotFound
	}
	if inst.Spec.Meta.ControllerID != p.ControllerID {
		return provider.ErrNotOwned
	}
	inst.Running = false
	return nil
}

// Delete implements provider.Provider.
func (p *Provider) Delete(_ context.Context, name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record("delete %s", name)
	inst, ok := p.instances[name]
	if !ok {
		return provider.ErrNotFound
	}
	if inst.Spec.Meta.ControllerID != p.ControllerID {
		return provider.ErrNotOwned
	}
	delete(p.instances, name)
	return nil
}

// List implements provider.Provider.
func (p *Provider) List(context.Context) ([]provider.Owned, []provider.Foreign, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var owned []provider.Owned
	foreign := append([]provider.Foreign(nil), p.foreign...)
	for name, inst := range p.instances {
		if inst.Spec.Meta.ControllerID == p.ControllerID {
			owned = append(owned, provider.Owned{Name: name, Running: inst.Running, Meta: inst.Spec.Meta})
		} else {
			foreign = append(foreign, provider.Foreign{Name: name, Running: inst.Running, Prefixed: strings.HasPrefix(name, "bivouac-")})
		}
	}
	return owned, foreign, nil
}

// CollectDiagnostics implements provider.Provider.
func (p *Provider) CollectDiagnostics(ctx context.Context, name, dir string) error {
	p.mu.Lock()
	p.record("diag %s", name)
	hang := p.HangDiagnostics
	p.mu.Unlock()
	if hang {
		<-ctx.Done()
		return ctx.Err()
	}
	return os.WriteFile(filepath.Join(dir, "runner.log"), []byte("fake runner log for "+name+"\n"), 0o600)
}

// MarkReady unblocks WaitReady.
func (p *Provider) MarkReady(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	inst, ok := p.instances[name]
	if !ok {
		p.preReady[name] = true
		return
	}
	select {
	case <-inst.ready:
	default:
		close(inst.ready)
	}
}

// MarkJobRunning flips the runner to running.
func (p *Provider) MarkJobRunning(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if inst, ok := p.instances[name]; ok {
		inst.Runner.State = provider.RunnerRunning
	}
}

// ExitRunner makes the runner exit with code.
func (p *Provider) ExitRunner(name string, code int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if inst, ok := p.instances[name]; ok {
		inst.Runner = provider.RunnerStatus{State: provider.RunnerExited, ExitCode: code}
		inst.exitCode = code
	}
}

// Kill simulates the VM dying: not running, runner absent.
func (p *Provider) Kill(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if inst, ok := p.instances[name]; ok {
		inst.Running = false
		inst.Runner = provider.RunnerStatus{State: provider.RunnerAbsent}
	}
}

// CallLog returns a copy of the recorded calls.
func (p *Provider) CallLog() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.Calls...)
}

// Names returns the names of guests the fake currently holds.
func (p *Provider) Names() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var names []string
	for n := range p.instances {
		names = append(names, n)
	}
	return names
}

// Get returns the fake's record for name.
func (p *Provider) Get(name string) (*Instance, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	inst, ok := p.instances[name]
	if !ok {
		return nil, false
	}
	cp := *inst
	return &cp, true
}

// SetRunnerJob models the official runner hook reporting a job.
func (p *Provider) SetRunnerJob(name string, job provider.RunnerJob) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if inst, ok := p.instances[name]; ok {
		inst.Runner.State = provider.RunnerRunning
		inst.Runner.Job = &job
	}
}
