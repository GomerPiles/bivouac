//go:build windows

// Package hcsvm runs Windows guests through bivouac's own VM host, which
// drives the Host Compute Service directly. The manager-side provider holds no
// privilege: it asks the VM host for guests over its authorized pipe and talks
// to each guest itself over HvSocket, which the guest's service table grants
// to this account alone.
//
// This first increment drives the prepared image's existing guest stack: App
// Sandbox's guest agent, OpenSSH and the shared winrunner adapter.
package hcsvm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/diag"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/vmhost"
	"github.com/GomerPiles/bivouac/internal/winguest"
	"github.com/GomerPiles/bivouac/internal/winhost"
	"github.com/GomerPiles/bivouac/internal/winrunner"
)

// Host is the VM host's pipe client.
type Host interface {
	Info(context.Context) (vmhost.Info, error)
	Create(context.Context, vmhost.CreateRequest) (vmhost.GuestInfo, error)
	Status(context.Context, string) (vmhost.GuestInfo, error)
	Destroy(context.Context, string) error
	List(context.Context) ([]vmhost.GuestInfo, error)
}

// Transport opens an authenticated session to a running guest.
type Transport interface {
	Open(ctx context.Context, name, runtimeID string, pin Pin) (Session, error)
}

// Session runs fixed commands and sends fixed files in one guest.
type Session interface {
	Run(ctx context.Context, command string, stdin []byte, limit int) ([]byte, error)
	Send(ctx context.Context, name string, data io.Reader, size int64) error
	Close() error
}

// Pin records and checks a guest's SSH host key fingerprint, so a manager
// that reconnects, for example after a restart, refuses a different key.
type Pin interface {
	Check(fingerprint string) error
}

type Options struct {
	Name         string
	ControllerID string
	// Image is the VM host's configured image name.
	Image string
	// GuestName and GuestUser are the prepared image's Windows computer name
	// and console user, which the guest adapter checks.
	GuestName     string
	GuestUser     string
	CPU           uint32
	MemoryMB      uint64
	LazyMemory    bool
	GPU           bool
	RunnerDir     string
	RunnerArchive string
	RunnerSHA256  string
	// Helper is this executable, copied into each guest as its adapter.
	Helper string
	// StateDir holds per-guest host key pins.
	StateDir string
}

const (
	guestHelper = `C:\ProgramData\Bivouac\Guest\bivouac.exe`
	control     = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File bivouac-control.ps1 -Mode "
	preflight   = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File bivouac-preflight.ps1"
	// The operation bound covers a VM host create or destroy and its cleanup.
	operationTimeout = 5 * time.Minute
)

type Provider struct {
	opts      Options
	host      Host
	transport Transport

	mu       sync.Mutex
	sessions map[string]Session
}

var _ provider.Provider = (*Provider)(nil)

func New(opts Options, host Host, transport Transport) (*Provider, error) {
	if opts.Name == "" || opts.ControllerID == "" || opts.Image == "" || opts.GuestName == "" || opts.GuestUser == "" || host == nil || transport == nil {
		return nil, errors.New("invalid HCS provider dependencies")
	}
	if opts.CPU < 1 || opts.MemoryMB < 1024 || !winrunner.ValidRunnerDir(opts.RunnerDir) || !filepath.IsAbs(opts.Helper) || !filepath.IsAbs(opts.StateDir) {
		return nil, errors.New("HCS provider needs bounded resources, a runner directory, the helper and a state directory")
	}
	if (opts.RunnerArchive == "") != (opts.RunnerSHA256 == "") {
		return nil, errors.New("runner archive requires its SHA-256")
	}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, err
	}
	return &Provider{opts: opts, host: host, transport: transport, sessions: map[string]Session{}}, nil
}

func (p *Provider) Name() string { return p.opts.Name }

func (p *Provider) Capabilities() provider.Capabilities {
	gpu := provider.GPUNone
	if p.opts.GPU {
		gpu = provider.GPUParavirtualized
	}
	return provider.Capabilities{GPU: gpu, DesktopSession: true, DisplayTransport: "none", OperationTimeout: operationTimeout}
}

func (p *Provider) prefix() string { return "bivouac-" + p.opts.Name + "-" }

// owned proves a VM host guest is this controller's: the VM host returns only
// this account's guests, and the labels name this controller and instance.
func (p *Provider) owned(g vmhost.GuestInfo) bool {
	id := strings.TrimPrefix(g.Name, p.prefix())
	return strings.HasPrefix(g.Name, p.prefix()) && g.Labels["controller_id"] == p.opts.ControllerID && g.Labels["instance_id"] == id
}

func meta(g vmhost.GuestInfo) provider.Metadata {
	return provider.Metadata{ControllerID: g.Labels["controller_id"], InstanceID: g.Labels["instance_id"], CreatedAt: g.Labels["created_at"]}
}

// Create asks the VM host to create, start and GPU-assign the guest. The VM
// host owns its native lifetime from then on.
func (p *Provider) Create(ctx context.Context, spec provider.Spec) error {
	if spec.Meta.ControllerID != p.opts.ControllerID || spec.Name != p.prefix()+spec.Meta.InstanceID {
		return provider.ErrNotOwned
	}
	labels := map[string]string{"controller_id": spec.Meta.ControllerID, "instance_id": spec.Meta.InstanceID}
	if spec.Meta.CreatedAt != "" {
		labels["created_at"] = spec.Meta.CreatedAt
	}
	_, err := p.host.Create(ctx, vmhost.CreateRequest{
		Name: spec.Name, Image: p.opts.Image, CPU: p.opts.CPU, MemoryMB: p.opts.MemoryMB, LazyMemory: p.opts.LazyMemory, GPU: p.opts.GPU,
		Services: []string{winguest.AgentService, winguest.SSHService}, Labels: labels,
	})
	return err
}

// guest returns this controller's running guest.
func (p *Provider) guest(ctx context.Context, name string) (vmhost.GuestInfo, error) {
	if !strings.HasPrefix(name, p.prefix()) {
		return vmhost.GuestInfo{}, provider.ErrNotOwned
	}
	g, err := p.host.Status(ctx, name)
	if vmhost.IsCode(err, vmhost.CodeNotFound) {
		return vmhost.GuestInfo{}, provider.ErrNotFound
	}
	if vmhost.IsCode(err, vmhost.CodeForeign) {
		return vmhost.GuestInfo{}, provider.ErrNotOwned
	}
	if err != nil {
		return vmhost.GuestInfo{}, err
	}
	if !p.owned(g) {
		return vmhost.GuestInfo{}, provider.ErrNotOwned
	}
	return g, nil
}

// Start confirms the VM host's guest is running; creation already booted it.
func (p *Provider) Start(ctx context.Context, name string, log io.Writer) error {
	g, err := p.guest(ctx, name)
	if err != nil {
		return err
	}
	if g.State != vmhost.StateRunning {
		return errors.New("guest is not running")
	}
	_, err = io.WriteString(log, "VM host guest running; its network is attached by the VM host\n")
	return err
}

func (p *Provider) session(ctx context.Context, name string) (Session, vmhost.GuestInfo, error) {
	g, err := p.guest(ctx, name)
	if err != nil {
		return nil, g, err
	}
	if g.State != vmhost.StateRunning {
		return nil, g, errors.New("guest is not running")
	}
	p.mu.Lock()
	s := p.sessions[name]
	p.mu.Unlock()
	if s != nil {
		return s, g, nil
	}
	s, err = p.transport.Open(ctx, name, g.RuntimeID, filePin{path: p.pinPath(g)})
	if err != nil {
		return nil, g, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing := p.sessions[name]; existing != nil {
		_ = s.Close()
		return existing, g, nil
	}
	p.sessions[name] = s
	return s, g, nil
}

// drop discards a session after a transport failure; the next call reconnects.
func (p *Provider) drop(name string, s Session) {
	p.mu.Lock()
	if p.sessions[name] == s {
		delete(p.sessions, name)
	}
	p.mu.Unlock()
	_ = s.Close()
}

func (p *Provider) run(ctx context.Context, name, command string, stdin []byte, limit int) ([]byte, error) {
	s, _, err := p.session(ctx, name)
	if err != nil {
		return nil, err
	}
	out, err := s.Run(ctx, command, stdin, limit)
	var transport provider.TransportFailure
	if errors.As(err, &transport) {
		p.drop(name, s)
	}
	return out, err
}

func (p *Provider) config(g vmhost.GuestInfo) ([]byte, error) {
	c := winrunner.Config{NativeName: p.opts.GuestName, RunnerName: g.Name, ControllerID: p.opts.ControllerID, User: p.opts.GuestUser, RunnerDir: p.opts.RunnerDir, Archive: p.opts.RunnerArchive != "", ArchiveSHA256: p.opts.RunnerSHA256}
	if g.Network != nil {
		c.Address, c.Gateway, c.Prefix, c.MAC = g.Network.Address, g.Network.Gateway, g.Network.Prefix, g.Network.MAC
	}
	return json.Marshal(c)
}

// WaitReady waits for the agent and SSH, proves the intended console session,
// then installs the fixed adapter and prepares the runner and its tasks.
func (p *Provider) WaitReady(ctx context.Context, name string) error {
	s, g, err := p.session(ctx, name)
	if err != nil {
		return err
	}
	if g.Network == nil {
		return errors.New("the VM host attached no network; the runner cannot reach GitHub")
	}
	config, err := p.config(g)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{"bivouac-preflight.ps1", []byte(winrunner.PreflightScript)}, {"bivouac-config.json", config}} {
		if err = s.Send(ctx, f.name, strings.NewReader(string(f.data)), int64(len(f.data))); err != nil {
			return err
		}
	}
	out, err := s.Run(ctx, preflight, nil, 4096)
	if err != nil {
		return err
	}
	var console struct {
		Ready   bool   `json:"ready"`
		Session uint32 `json:"session"`
	}
	if json.Unmarshal(out, &console) != nil || !console.Ready || console.Session == 0 || console.Session == ^uint32(0) {
		return errors.New("guest console readiness was not proven")
	}
	if err = s.Send(ctx, "bivouac-control.ps1", strings.NewReader(winrunner.ControlScript), int64(len(winrunner.ControlScript))); err != nil {
		return err
	}
	if err = sendFile(ctx, s, p.opts.Helper, "bivouac-helper.exe", ""); err != nil {
		return err
	}
	if p.opts.RunnerArchive != "" {
		if err = sendFile(ctx, s, p.opts.RunnerArchive, "bivouac-runner.zip", p.opts.RunnerSHA256); err != nil {
			return err
		}
	}
	out, err = s.Run(ctx, control+"prepare", nil, 4096)
	if err != nil {
		return err
	}
	var desktop struct {
		Ready   bool   `json:"ready"`
		Session uint32 `json:"session"`
		Desktop string `json:"desktop"`
	}
	if json.Unmarshal(out, &desktop) != nil || !desktop.Ready || desktop.Session == 0 || desktop.Desktop != "Default" {
		return errors.New("guest interactive desktop readiness was not proven")
	}
	return nil
}

func sendFile(ctx context.Context, s Session, path, name, sha256 string) error {
	if sha256 != "" {
		if err := winrunner.VerifyArchive(path, sha256); err != nil {
			return err
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("guest transfer source is not a regular file")
	}
	return s.Send(ctx, name, f, info.Size())
}

func (p *Provider) StartRunner(ctx context.Context, name string, jit []byte) error {
	if len(jit) == 0 || len(jit) > 128<<10 {
		return errors.New("invalid bounded runner JIT configuration")
	}
	if _, err := p.run(ctx, name, guestHelper+" guest windows seed-jit", jit, 4096); err != nil {
		return err
	}
	_, err := p.run(ctx, name, control+"start", nil, 4096)
	return err
}

func (p *Provider) StopRunner(ctx context.Context, name string) error {
	_, err := p.run(ctx, name, control+"stop", nil, 4096)
	if errors.Is(err, provider.ErrNotFound) {
		return nil
	}
	return err
}

// RunnerStatus calls the adapter directly rather than through PowerShell; it
// runs every few seconds for the whole job.
func (p *Provider) RunnerStatus(ctx context.Context, name string) (provider.RunnerStatus, error) {
	out, err := p.run(ctx, name, guestHelper+" guest windows status", nil, 4096)
	if errors.Is(err, provider.ErrNotFound) {
		return provider.RunnerStatus{State: provider.RunnerAbsent}, nil
	}
	if err != nil {
		return provider.RunnerStatus{}, err
	}
	var status provider.RunnerStatus
	if json.Unmarshal(out, &status) != nil {
		return provider.RunnerStatus{}, errors.New("invalid bounded guest runner status")
	}
	switch status.State {
	case provider.RunnerAbsent, provider.RunnerStarting, provider.RunnerListening, provider.RunnerRunning, provider.RunnerExited:
		return status, nil
	}
	return provider.RunnerStatus{}, errors.New("unknown guest runner status")
}

func (p *Provider) Status(ctx context.Context, name string) (provider.Status, error) {
	g, err := p.guest(ctx, name)
	if errors.Is(err, provider.ErrNotFound) {
		return provider.Status{}, nil
	}
	if errors.Is(err, provider.ErrNotOwned) {
		return provider.Status{Exists: true}, nil
	}
	if err != nil {
		return provider.Status{}, err
	}
	return provider.Status{Exists: true, Running: g.State == vmhost.StateRunning, Owned: true, Meta: meta(g)}, nil
}

// Stop destroys the disposable guest: the VM host terminates it and confirms
// absence before removing its storage. There is nothing to keep.
func (p *Provider) Stop(ctx context.Context, name string, _ time.Duration) error {
	return p.Delete(ctx, name)
}

func (p *Provider) Delete(ctx context.Context, name string) error {
	if !strings.HasPrefix(name, p.prefix()) {
		return provider.ErrNotOwned
	}
	g, err := p.guest(ctx, name)
	if errors.Is(err, provider.ErrNotFound) {
		p.forget(name)
		return nil
	}
	if err != nil {
		return err
	}
	p.mu.Lock()
	s := p.sessions[name]
	delete(p.sessions, name)
	p.mu.Unlock()
	if s != nil {
		_ = s.Close()
	}
	if err = p.host.Destroy(ctx, name); err != nil && !vmhost.IsCode(err, vmhost.CodeNotFound) {
		return err
	}
	_ = os.Remove(p.pinPath(g))
	return nil
}

func (p *Provider) forget(name string) {
	p.mu.Lock()
	s := p.sessions[name]
	delete(p.sessions, name)
	p.mu.Unlock()
	if s != nil {
		_ = s.Close()
	}
}

func (p *Provider) List(ctx context.Context) ([]provider.Owned, []provider.Foreign, error) {
	guests, err := p.host.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	var owned []provider.Owned
	var foreign []provider.Foreign
	for _, g := range guests {
		running := g.State == vmhost.StateRunning
		if p.owned(g) {
			owned = append(owned, provider.Owned{Name: g.Name, Running: running, Meta: meta(g)})
		} else {
			foreign = append(foreign, provider.Foreign{Name: g.Name, Running: running, Prefixed: strings.HasPrefix(g.Name, "bivouac-")})
		}
	}
	return owned, foreign, nil
}

func (p *Provider) CollectDiagnostics(ctx context.Context, name, dir string) error {
	out, err := p.run(ctx, name, guestHelper+" guest windows diagnostics", nil, 45<<20)
	if errors.Is(err, provider.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	decoded, err := io.ReadAll(io.LimitReader(base64.NewDecoder(base64.StdEncoding, strings.NewReader(strings.TrimSpace(string(out)))), 32<<20+1))
	if err != nil || len(decoded) > 32<<20 {
		return errors.New("invalid bounded guest diagnostics stream")
	}
	staging, err := winhost.PrivateDirectory(p.opts.StateDir)
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	archive := filepath.Join(staging, "diagnostics.zip")
	if err = os.WriteFile(archive, decoded, 0o600); err != nil {
		return err
	}
	return diag.ExtractGuestArchive(archive, dir)
}

// Close ends every guest session. Guests keep running in the VM host.
func (p *Provider) Close() {
	p.mu.Lock()
	sessions := p.sessions
	p.sessions = map[string]Session{}
	p.mu.Unlock()
	for _, s := range sessions {
		_ = s.Close()
	}
}

func (p *Provider) pinPath(g vmhost.GuestInfo) string {
	return filepath.Join(p.opts.StateDir, g.Labels["instance_id"]+".hostkey")
}

// filePin keeps a guest's host key fingerprint (public data) beside the
// manager's state, so a restarted manager can adopt only the same guest.
type filePin struct{ path string }

func (f filePin) Check(fingerprint string) error {
	if len(fingerprint) != 64 || strings.Trim(fingerprint, "0123456789abcdef") != "" {
		return errors.New("invalid host key fingerprint")
	}
	pinned, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(f.path, []byte(fingerprint), 0o600)
	}
	if err != nil {
		return err
	}
	if string(pinned) != fingerprint {
		return provider.SSHHostKey
	}
	return nil
}
