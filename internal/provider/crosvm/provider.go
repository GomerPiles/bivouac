package crosvm

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/provider"
)

// Backend owns only recorded overlays and native supervised processes.
// Verify must prove the PID/creation time/image, fixed launch and host snapshot.
// Deletion retains the reservation until every child and disk is absent.
type Backend interface {
	Create(context.Context, provider.Spec) error
	Start(context.Context, string, io.Writer) error
	WaitReady(context.Context, string) (Record, error)
	Lookup(context.Context, string) (Record, provider.Status, error)
	Verify(context.Context, string) error
	Stop(context.Context, string, time.Duration) error
	Delete(context.Context, string) error
	List(context.Context) ([]provider.Owned, []provider.Foreign, error)
}
type Guest interface {
	Ready(context.Context, Record) error
	StartRunner(context.Context, Record, []byte) error
	StopRunner(context.Context, Record) error
	RunnerStatus(context.Context, Record) (provider.RunnerStatus, error)
	CollectDiagnostics(context.Context, Record, string) error
	// Forget removes per-instance host state, such as pinned host keys, after
	// the instance is confirmed deleted. It must be idempotent.
	Forget(instanceID string) error
}
type Provider struct {
	opts    Options
	backend Backend
	guest   Guest
	cache   *cache.Service
}

// SetCache attaches before manager admission. Guest setup follows current
// ownership and network verification; revocation follows confirmed deletion.
func (p *Provider) SetCache(service *cache.Service) {
	p.cache = service
	if guest, ok := p.guest.(interface{ SetCache(*cache.Service) }); ok {
		guest.SetCache(service)
	}
}

var _ provider.Provider = (*Provider)(nil)

func New(opts Options, backend Backend, guest Guest) (*Provider, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if backend == nil || guest == nil {
		return nil, errors.New("crosvm dependencies are required")
	}
	return &Provider{opts: opts, backend: backend, guest: guest}, nil
}
func (p *Provider) Name() string { return p.opts.Name }
func (p *Provider) Close() {
	if closer, ok := p.backend.(interface{ Close() }); ok {
		closer.Close()
	}
}

func (p *Provider) CheckLocal() error {
	if checker, ok := p.backend.(interface{ CheckLocal() error }); ok {
		return checker.CheckLocal()
	}
	return errors.New("native readiness checker unavailable")
}
func (p *Provider) Capabilities() provider.Capabilities {
	gpu := provider.GPUNone
	if p.opts.GPU {
		gpu = provider.GPUParavirtualized
	}
	// Windowed Linux jobs supply their compositor inside the disposable guest
	// or container. Do not claim an interactive desktop merely from GPU mode.
	return provider.Capabilities{GPU: gpu, DisplayTransport: "none"}
}
func (p *Provider) managed(name string) bool {
	return strings.HasPrefix(name, "bivouac-"+p.opts.Name+"-")
}
func (p *Provider) lookup(ctx context.Context, name string) (Record, provider.Status, error) {
	if !p.managed(name) {
		return Record{}, provider.Status{}, provider.ErrNotOwned
	}
	r, s, err := p.backend.Lookup(ctx, name)
	if err != nil {
		return Record{}, s, err
	}
	if r.Name != name || r.Meta.ControllerID != p.opts.ControllerID || !s.Owned || s.Meta != r.Meta {
		return Record{}, s, provider.ErrNotOwned
	}
	if _, _, err := Launch(p.opts, r); err != nil {
		return Record{}, s, err
	}
	return r, s, nil
}
func (p *Provider) Create(ctx context.Context, spec provider.Spec) (result error) {
	started := time.Now()
	defer func() { logStartup(spec.Name, "clone", started, result) }()
	if !p.managed(spec.Name) || spec.Meta.ControllerID != p.opts.ControllerID {
		return provider.ErrNotOwned
	}
	return p.backend.Create(ctx, spec)
}
func (p *Provider) Start(ctx context.Context, name string, out io.Writer) (result error) {
	started := time.Now()
	defer func() { logStartup(name, "native_start", started, result) }()
	if _, _, err := p.lookup(ctx, name); err != nil {
		return err
	}
	return p.backend.Start(ctx, name, out)
}
func (p *Provider) WaitReady(ctx context.Context, name string) error {
	if _, _, err := p.lookup(ctx, name); err != nil {
		return err
	}
	started := time.Now()
	r, err := p.backend.WaitReady(ctx, name)
	logStartup(name, "ssh_available", started, err)
	if err != nil {
		return err
	}
	if r.Name != name || r.Meta.ControllerID != p.opts.ControllerID {
		return provider.ErrNotOwned
	}
	if _, _, err := Launch(p.opts, r); err != nil {
		return err
	}
	if err := p.backend.Verify(ctx, name); err != nil {
		return err
	}
	return p.guest.Ready(ctx, r)
}
func (p *Provider) StartRunner(ctx context.Context, name string, jit []byte) error {
	if len(jit) == 0 || len(jit) > 128<<10 {
		return errors.New("invalid bounded JIT input")
	}
	r, s, err := p.lookup(ctx, name)
	if err != nil {
		return err
	}
	if !s.Running {
		return errors.New("owned Linux VM is unavailable")
	}
	if err := p.backend.Verify(ctx, name); err != nil {
		return err
	}
	return p.guest.StartRunner(ctx, r, jit)
}
func (p *Provider) StopRunner(ctx context.Context, name string) error {
	r, s, err := p.lookup(ctx, name)
	if err != nil {
		return err
	}
	if !s.Running {
		return nil
	}
	return p.guest.StopRunner(ctx, r)
}
func (p *Provider) RunnerStatus(ctx context.Context, name string) (provider.RunnerStatus, error) {
	r, s, err := p.lookup(ctx, name)
	if err != nil {
		return provider.RunnerStatus{}, err
	}
	if !s.Running {
		return provider.RunnerStatus{State: provider.RunnerAbsent}, nil
	}
	if err := p.backend.Verify(ctx, name); err != nil {
		return provider.RunnerStatus{}, err
	}
	return p.guest.RunnerStatus(ctx, r)
}
func (p *Provider) Status(ctx context.Context, name string) (provider.Status, error) {
	_, s, err := p.lookup(ctx, name)
	if errors.Is(err, provider.ErrNotFound) {
		return provider.Status{}, nil
	}
	return s, err
}
func (p *Provider) Stop(ctx context.Context, name string, timeout time.Duration) error {
	if _, _, err := p.lookup(ctx, name); err != nil {
		return err
	}
	return p.backend.Stop(ctx, name, timeout)
}
func (p *Provider) Delete(ctx context.Context, name string) error {
	if !p.managed(name) {
		return provider.ErrNotOwned
	}
	id := strings.TrimPrefix(name, "bivouac-"+p.opts.Name+"-")
	if !validID(id) {
		return provider.ErrNotOwned
	}
	if err := p.backend.Delete(ctx, name); err != nil {
		return err
	}
	if p.cache != nil {
		p.cache.Revoke(name)
	}
	// A retry after a failure here finds the instance absent and forgets again.
	return p.guest.Forget(id)
}
func (p *Provider) List(ctx context.Context) ([]provider.Owned, []provider.Foreign, error) {
	owned, foreign, err := p.backend.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	var mine []provider.Owned
	for _, r := range owned {
		if p.managed(r.Name) && r.Meta.ControllerID == p.opts.ControllerID {
			mine = append(mine, r)
		} else {
			foreign = append(foreign, provider.Foreign{Name: r.Name, Running: r.Running, Prefixed: strings.HasPrefix(r.Name, "bivouac-")})
		}
	}
	return mine, foreign, nil
}
func (p *Provider) CollectDiagnostics(ctx context.Context, name, dir string) error {
	r, s, err := p.lookup(ctx, name)
	if err != nil {
		return err
	}
	if !s.Running {
		return nil
	}
	return p.guest.CollectDiagnostics(ctx, r, dir)
}
