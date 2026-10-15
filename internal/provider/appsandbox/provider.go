package appsandbox

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/provider"
)

// Lease contains only non-secret native ownership and guest connection data.
// It is issued by the privileged backend after checking protected records.
type Lease struct {
	Record  CloneRecord `json:"record"`
	VM      VM          `json:"vm"`
	SSH     SSH         `json:"ssh"`
	Address string      `json:"address"`
	Gateway string      `json:"gateway"`
	Prefix  int         `json:"prefix"`
	MAC     string      `json:"mac"`
}

// Backend owns privileged creation, protected markers, networking and native
// cleanup. Prepare must install and verify policy before returning a lease.
// Verify checks current native policy; it must never silently repair a running
// guest or accept a stale readiness flag. Delete confirms both VM and network
// absence before removing its durable record, including partial creations.
type Backend interface {
	Create(context.Context, CloneRecord) error
	Lookup(context.Context, string) (Lease, error)
	Start(context.Context, string) error
	Prepare(context.Context, string) (Lease, error)
	Verify(context.Context, string) error
	Stop(context.Context, string, time.Duration) error
	Delete(context.Context, string) error
	List(context.Context) ([]provider.Owned, []provider.Foreign, error)
}

// Guest uses an authenticated channel bound to the owned native VM's HvSocket
// forward. Runner bootstrap/status is independent of the privileged broker.
type Guest interface {
	Preflight(context.Context, Lease) error
	Ready(context.Context, Lease) error
	StartRunner(context.Context, Lease, []byte) error
	StopRunner(context.Context, Lease) error
	RunnerStatus(context.Context, Lease) (provider.RunnerStatus, error)
	CollectDiagnostics(context.Context, Lease, string) error
	// Forget discards host-side per-instance transport state (the pinned
	// host key) after the backend confirms deletion. Absence is success.
	Forget(name string) error
}

type Options struct {
	Name         string
	Root         string
	ControllerID string
	DiskGB       int
	GPU          bool
	HostLimit    int
}

// Provider connects App Sandbox lifecycle to the portable manager contract.
// It never starts the elevated daemon or adopts a native VM by its name alone.
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
	if !identifier(opts.Name, 31) || !identifier(opts.ControllerID, 64) || opts.Root == "" || opts.DiskGB < 16 || backend == nil || guest == nil {
		return nil, errors.New("invalid App Sandbox provider dependencies")
	}
	return &Provider{opts: opts, backend: backend, guest: guest}, nil
}

func (p *Provider) Name() string { return p.opts.Name }
func (p *Provider) Capabilities() provider.Capabilities {
	gpu := provider.GPUNone
	if p.opts.GPU {
		gpu = provider.GPUParavirtualized
	}
	return provider.Capabilities{GPU: gpu, DesktopSession: true, DisplayTransport: "none", HostLimit: p.opts.HostLimit, OperationTimeout: operationTimeout}
}

func (p *Provider) Create(ctx context.Context, spec provider.Spec) error {
	if spec.Meta.ControllerID != p.opts.ControllerID || !strings.HasPrefix(spec.Name, "bivouac-"+p.opts.Name+"-") {
		return provider.ErrNotOwned
	}
	gpu := 0
	if p.opts.GPU {
		gpu = 1
	}
	r, err := PlanClone(p.opts.Root, spec, p.opts.DiskGB, gpu)
	if err != nil {
		return err
	}
	return p.backend.Create(ctx, r)
}

func (p *Provider) lease(ctx context.Context, name string) (Lease, error) {
	if !strings.HasPrefix(name, "bivouac-"+p.opts.Name+"-") {
		return Lease{}, provider.ErrNotOwned
	}
	l, err := p.backend.Lookup(ctx, name)
	if err != nil {
		return Lease{}, err
	}
	if l.Record.RunnerName != name || l.Record.Meta.ControllerID != p.opts.ControllerID {
		return Lease{}, provider.ErrNotOwned
	}
	// The broker supplies records read through its protected storage root;
	// repeat structural/native checks at the normal-user boundary as well.
	if l.VM.Name != "" {
		if err = CheckClone(p.opts.Root, p.opts.ControllerID, l.Record, l.Record, l.Record, l.VM); err != nil {
			return Lease{}, err
		}
	}
	return l, nil
}

func (p *Provider) Start(ctx context.Context, name string, log io.Writer) error {
	if _, err := p.lease(ctx, name); err != nil {
		return err
	}
	if err := p.backend.Start(ctx, name); err != nil {
		return err
	}
	_, err := io.WriteString(log, "App Sandbox owned disposable guest started without native networking\n")
	return err
}

func (p *Provider) WaitReady(ctx context.Context, name string) error {
	for {
		l, err := p.lease(ctx, name)
		if err != nil {
			return err
		}
		if l.VM.Name == "" {
			return provider.ErrNotFound
		}
		if l.VM.Running && !l.VM.Building && l.VM.InstallComplete && l.VM.AgentOnline && l.SSH.ForwardReady() {
			// Native SSH readiness precedes OOBE/logon on generalized images.
			// Keep the NIC absent until the intended console user is ready.
			if err = p.guest.Preflight(ctx, l); err != nil {
				return err
			}
			l, err = p.backend.Prepare(ctx, name)
			if err != nil {
				return err
			}
			if !l.SSH.ForwardReady() {
				return errors.New("owned guest SSH forwarding not ready")
			}
			if err = p.backend.Verify(ctx, name); err != nil {
				return err
			}
			return p.guest.Ready(ctx, l)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (p *Provider) StartRunner(ctx context.Context, name string, jit []byte) error {
	if len(jit) == 0 || len(jit) > 128*1024 {
		return errors.New("invalid bounded runner JIT configuration")
	}
	l, err := p.lease(ctx, name)
	if err != nil {
		return err
	}
	if !l.VM.Running || !l.SSH.ForwardReady() {
		return errors.New("owned runner guest unavailable")
	}
	if err = p.backend.Verify(ctx, name); err != nil {
		return err
	}
	return p.guest.StartRunner(ctx, l, jit)
}

func (p *Provider) StopRunner(ctx context.Context, name string) error {
	l, err := p.lease(ctx, name)
	if err != nil {
		return err
	}
	if l.VM.Name == "" || !l.VM.Running {
		return nil
	}
	return p.guest.StopRunner(ctx, l)
}

func (p *Provider) RunnerStatus(ctx context.Context, name string) (provider.RunnerStatus, error) {
	l, err := p.lease(ctx, name)
	if err != nil {
		return provider.RunnerStatus{}, err
	}
	if l.VM.Name == "" || !l.VM.Running {
		return provider.RunnerStatus{State: provider.RunnerAbsent}, nil
	}
	if err = p.backend.Verify(ctx, name); err != nil {
		return provider.RunnerStatus{}, err
	}
	return p.guest.RunnerStatus(ctx, l)
}

func (p *Provider) Status(ctx context.Context, name string) (provider.Status, error) {
	l, err := p.lease(ctx, name)
	if errors.Is(err, provider.ErrNotFound) {
		return provider.Status{}, nil
	}
	if err != nil {
		return provider.Status{}, err
	}
	return provider.Status{Exists: l.VM.Name != "", Running: l.VM.Running, Owned: true, Meta: l.Record.Meta}, nil
}

func (p *Provider) Stop(ctx context.Context, name string, timeout time.Duration) error {
	if _, err := p.lease(ctx, name); err != nil {
		return err
	}
	return p.backend.Stop(ctx, name, timeout)
}
func (p *Provider) Delete(ctx context.Context, name string) error {
	if !strings.HasPrefix(name, "bivouac-"+p.opts.Name+"-") {
		return provider.ErrNotOwned
	}
	// Delete remains a backend operation after native VM absence: remaining
	// endpoints, switch ports and partial intent still consume the reservation.
	if err := p.backend.Delete(ctx, name); err != nil {
		return err
	}
	if p.cache != nil {
		p.cache.Revoke(name)
	}
	return p.guest.Forget(name)
}
func (p *Provider) List(ctx context.Context) ([]provider.Owned, []provider.Foreign, error) {
	owned, foreign, err := p.backend.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	var mine []provider.Owned
	for _, instance := range owned {
		if strings.HasPrefix(instance.Name, "bivouac-"+p.opts.Name+"-") {
			mine = append(mine, instance)
		} else {
			foreign = append(foreign, provider.Foreign{Name: instance.Name, Running: instance.Running, Prefixed: true})
		}
	}
	return mine, foreign, nil
}

func (p *Provider) Close() {
	if closer, ok := p.backend.(interface{ Close() }); ok {
		closer.Close()
	}
}
func (p *Provider) CollectDiagnostics(ctx context.Context, name, dir string) error {
	l, err := p.lease(ctx, name)
	if err != nil {
		return err
	}
	if l.VM.Name == "" || !l.VM.Running {
		return nil
	}
	return p.guest.CollectDiagnostics(ctx, l, dir)
}
