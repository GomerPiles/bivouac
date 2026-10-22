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
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/diag"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/vmhost"
	"github.com/GomerPiles/bivouac/internal/winguest"
	"github.com/GomerPiles/bivouac/internal/winhost"
	"github.com/GomerPiles/bivouac/internal/winrunner"
	"golang.org/x/crypto/ssh"
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
	// CacheClient opens a separate authenticated client with this session's
	// in-memory identity and host-key pin, over the transport that wrap
	// returns before the SSH handshake. Ownership passes to the caller.
	CacheClient(ctx context.Context, wrap func(net.Conn) net.Conn) (*ssh.Client, error)
	Close() error
}

// Pin records and checks a guest's SSH host key fingerprint, so a manager
// that reconnects, for example after a restart, refuses a different key.
type Pin interface {
	Check(fingerprint string) error
}

type Options struct {
	// Logger receives numeric startup observations; nil uses slog.Default().
	Logger *slog.Logger
	// Service is optional; nil leaves an operator-owned foreground host alone.
	Service      Service
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
	// clockSync reads a UTC time (ISO 8601, 7 fractional digits) from stdin,
	// advances it by the time since PowerShell started, sets the guest clock
	// to it and prints the guest's UTC time afterwards.
	clockSync    = `powershell.exe -NoProfile -NonInteractive -Command "$t=[DateTime]::ParseExact([Console]::In.ReadLine().Trim(),'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind); $t=$t.Add((Get-Date)-(Get-Process -Id $PID).StartTime); Set-Date -Date $t.ToLocalTime() | Out-Null; [DateTime]::UtcNow.ToString('o')"`
	maxClockSkew = 5 * time.Second
)

type Provider struct {
	opts      Options
	host      Host
	transport Transport
	now       func() time.Time // the host clock guests are set from
	logger    *slog.Logger

	mu       sync.Mutex
	sessions map[string]Session
	timings  map[string]instanceTiming // monotonic observations, never durable

	// cacheMu serializes attachment and revocation with provider shutdown.
	// The service owns the clients; this provider owns their per-guest grants.
	cacheMu     sync.Mutex
	cache       *cache.Service
	cacheGuests map[string]struct{}
	closed      bool
}

var _ provider.Provider = (*Provider)(nil)
var _ provider.Activator = (*Provider)(nil)

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
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Provider{opts: opts, host: host, transport: transport, now: time.Now, logger: logger, sessions: map[string]Session{}, timings: map[string]instanceTiming{}, cacheGuests: map[string]struct{}{}}, nil
}

func (p *Provider) Name() string { return p.opts.Name }

// SetCache is configured once, before guest operations begin.
func (p *Provider) SetCache(service *cache.Service) { p.cache = service }

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

// Create asks the VM host to create, start and GPU-assign the guest with an
// isolated network endpoint. The VM host owns its native lifetime from then on.
func (p *Provider) Create(ctx context.Context, spec provider.Spec) error {
	if spec.Meta.ControllerID != p.opts.ControllerID || spec.Name != p.prefix()+spec.Meta.InstanceID {
		return provider.ErrNotOwned
	}
	// Zero values use the configured size. Explicit manager reservations must
	// agree with the request: this provider uses its immutable Options to create.
	if (spec.Baseline != "" && spec.Baseline != p.opts.Image) ||
		(spec.CPU != 0 && (spec.CPU < 0 || uint64(spec.CPU) != uint64(p.opts.CPU))) ||
		(spec.MemoryMB != 0 && (spec.MemoryMB < 0 || uint64(spec.MemoryMB) != p.opts.MemoryMB)) {
		return errors.New("HCS spec image or resources disagree with provider settings")
	}
	labels := map[string]string{"controller_id": spec.Meta.ControllerID, "instance_id": spec.Meta.InstanceID}
	if spec.Meta.CreatedAt != "" {
		labels["created_at"] = spec.Meta.CreatedAt
	}
	started := time.Now()
	_, err := p.host.Create(ctx, vmhost.CreateRequest{
		Name: spec.Name, Image: p.opts.Image, CPU: p.opts.CPU, MemoryMB: p.opts.MemoryMB, LazyMemory: p.opts.LazyMemory, GPU: p.opts.GPU, Network: true,
		Services: []string{winguest.AgentService, winguest.SSHService}, Labels: labels,
	})
	if err == nil {
		returned := time.Now()
		p.mu.Lock()
		p.timings[spec.Name] = instanceTiming{createStarted: started, createReturned: returned}
		p.mu.Unlock()
	}
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
	_, err := p.waitReady(ctx, name)
	return err
}

// waitReady returns exactly the numeric report emitted to the daemon log, so
// lab results include partial observations even when readiness fails.
func (p *Provider) waitReady(ctx context.Context, name string) (report timingReport, err error) {
	p.mu.Lock()
	created := p.timings[name]
	p.mu.Unlock()
	t := newTiming(created.createStarted)
	if !created.createReturned.IsZero() {
		ms := created.createReturned.Sub(created.createStarted).Milliseconds()
		t.report.SpansMS["vmhost_create_ms"] = ms
		t.report.SpansMS["vmhost_create_since_create_ms"] = ms
	}
	ctx = context.WithValue(ctx, timingContextKey{}, t)
	defer func() {
		report = t.finish("wait_ready_total", err)
		p.emitTiming(ctx, "hcs readiness timings", report)
	}()
	err = p.ready(ctx, name, t)
	return report, err
}

func (p *Provider) ready(ctx context.Context, name string, t *timing) error {
	t.begin(stepSession)
	s, g, err := p.session(ctx, name)
	if err != nil {
		return err
	}
	t.begin(stepNetwork)
	if g.Network == nil {
		return errors.New("the VM host attached no network; the runner cannot reach GitHub")
	}
	t.begin(stepConfig)
	config, err := p.config(g)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
		step timingStep
	}{{"bivouac-preflight.ps1", []byte(winrunner.PreflightScript), stepDeliveryPreflight}, {"bivouac-config.json", config, stepDeliveryConfig}} {
		t.begin(f.step)
		if err = s.Send(ctx, f.name, strings.NewReader(string(f.data)), int64(len(f.data))); err != nil {
			return err
		}
	}
	t.begin(stepPreflight)
	out, err := s.Run(ctx, preflight, nil, 4096)
	if err != nil {
		return err
	}
	t.begin(stepConsoleProof)
	var console struct {
		Ready   bool   `json:"ready"`
		Session uint32 `json:"session"`
	}
	if json.Unmarshal(out, &console) != nil || !console.Ready || console.Session == 0 || console.Session == ^uint32(0) {
		return errors.New("guest console readiness was not proven")
	}
	t.begin(stepDeliveryControl)
	if err = s.Send(ctx, "bivouac-control.ps1", strings.NewReader(winrunner.ControlScript), int64(len(winrunner.ControlScript))); err != nil {
		return err
	}
	t.begin(stepDeliveryHelper)
	if err = sendFile(ctx, s, p.opts.Helper, "bivouac-helper.exe", ""); err != nil {
		return err
	}
	if p.opts.RunnerArchive != "" {
		t.begin(stepDeliveryRunner)
		if err = sendFile(ctx, s, p.opts.RunnerArchive, "bivouac-runner.zip", p.opts.RunnerSHA256); err != nil {
			return err
		}
	}
	t.begin(stepPrepare)
	out, err = s.Run(ctx, control+"prepare", nil, 4096)
	if err != nil {
		return err
	}
	t.begin(stepDesktopProof)
	var desktop struct {
		Ready   bool   `json:"ready"`
		Session uint32 `json:"session"`
		Desktop string `json:"desktop"`
	}
	if json.Unmarshal(out, &desktop) != nil || !desktop.Ready || desktop.Session == 0 || desktop.Desktop != "Default" {
		return errors.New("guest interactive desktop readiness was not proven")
	}
	t.begin(stepClockSync)
	return p.syncClock(ctx, s)
}

// syncClock sets the guest's clock from the host's. The guest reads its RTC,
// which holds host local time, in the image's own time zone, and nothing
// syncs it afterwards, so it can boot hours off; GitHub refuses the runner's
// tokens from such a clock. The time travels on stdin, never in the command.
func (p *Provider) syncClock(ctx context.Context, s Session) error {
	host := p.now().UTC().Format("2006-01-02T15:04:05.0000000Z07:00") + "\n"
	out, err := s.Run(ctx, clockSync, []byte(host), 256)
	if err != nil {
		return fmt.Errorf("set guest clock: %w", err)
	}
	guest, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(out)))
	if err != nil {
		return errors.New("guest clock was not reported")
	}
	skew := guest.Sub(p.now())
	if t := contextTiming(ctx); t != nil {
		t.report.SpansMS["clock_skew_ms"] = skew.Milliseconds()
	}
	if skew > maxClockSkew || skew < -maxClockSkew {
		return fmt.Errorf("guest clock is %s off the host's after correction", skew.Round(time.Second))
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

func (p *Provider) StartRunner(ctx context.Context, name string, jit []byte) (err error) {
	if len(jit) == 0 || len(jit) > 128<<10 {
		return errors.New("invalid bounded runner JIT configuration")
	}
	p.mu.Lock()
	created := p.timings[name]
	p.mu.Unlock()
	t := newTiming(created.createStarted)
	defer func() {
		p.emitTiming(ctx, "hcs launch timings", t.finish("launch_total", err))
	}()
	t.begin(stepCacheSetup)
	if err := p.prepareCache(ctx, name); err != nil {
		return err
	}
	t.begin(stepJITDelivery)
	jitStarted := time.Now()
	if _, err := p.run(ctx, name, guestHelper+" guest windows seed-jit", jit, 4096); err != nil {
		return err
	}
	t.begin(stepRunnerStart)
	_, err = p.run(ctx, name, control+"start", nil, 4096)
	if err == nil {
		p.mu.Lock()
		observed := p.timings[name]
		observed.jitStarted = jitStarted
		p.timings[name] = observed
		p.mu.Unlock()
	}
	return err
}

func (p *Provider) prepareCache(ctx context.Context, name string) error {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	if p.closed {
		return errors.New("HCS provider closed")
	}
	if p.cache == nil {
		return nil
	}
	// Repeat the same current ownership/running proof used before JIT. The
	// VM host reports quarantined guests as stopped; its guard owns policy.
	s, _, err := p.session(ctx, name)
	if err != nil {
		return err
	}
	if _, attached := p.cacheGuests[name]; attached {
		return nil // Transport loss uses upstream fallback, never reattachment.
	}
	loss := cache.NewSSHLoss()
	client, err := s.CacheClient(ctx, loss.Conn)
	if err == nil {
		var bootstrap []byte
		bootstrap, err = p.cache.AttachSSHClient(ctx, name, client, loss)
		if err == nil {
			_, err = p.run(ctx, name, guestHelper+" guest windows cache-setup", bootstrap, 4096)
		}
		clear(bootstrap)
	}
	if err != nil {
		p.cache.GuestUnavailable(name)
		p.cache.Revoke(name)
		if _, err := p.run(ctx, name, guestHelper+" guest windows cache-remove", nil, 4096); err != nil {
			return errors.New("remove incomplete guest cache adapter")
		}
		return nil
	}
	p.cacheGuests[name] = struct{}{}
	return nil
}

func (p *Provider) revokeCache(name string) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	if _, attached := p.cacheGuests[name]; attached {
		delete(p.cacheGuests, name)
		p.cache.Revoke(name)
	}
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
		if status.State == provider.RunnerListening || status.State == provider.RunnerRunning {
			p.observeListening(ctx, name)
		}
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
		p.revokeCache(name)
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
	p.revokeCache(name)
	_ = os.Remove(p.pinPath(g))
	p.mu.Lock()
	delete(p.timings, name)
	p.mu.Unlock()
	return nil
}

func (p *Provider) forget(name string) {
	p.mu.Lock()
	delete(p.timings, name)
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
	p.cacheMu.Lock()
	p.closed = true
	for name := range p.cacheGuests {
		p.cache.Revoke(name)
		delete(p.cacheGuests, name)
	}
	p.cacheMu.Unlock()
	p.mu.Lock()
	sessions := p.sessions
	p.sessions = map[string]Session{}
	p.timings = map[string]instanceTiming{}
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
