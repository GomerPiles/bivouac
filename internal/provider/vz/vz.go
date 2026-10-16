// Package vz is the macOS provider: disposable guests cloned from a local
// Tart-format baseline, run headless by bivouac's own Virtualization.framework
// helper, and driven through bivouac's guest agent so the runner lives in the
// guest's Aqua session. Tart may build baselines; bivouac runs them.
package vz

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/redact"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/vm"
)

//go:embed guest.sh
var guestScript []byte

// guestPath is where the bootstrap script lives inside each clone.
const guestPath = "/tmp/bivouac-guest"

// markerFile is written beside the VM's config.json after a clone and is
// deleted with the VM directory.
const markerFile = "bivouac.json"

// Provider implements provider.Provider on Tart-format VM directories.
type Provider struct {
	name           string
	cfg            config.VZ
	controllerID   string
	store          vm.Store // baselines and clones
	rt             Runtime
	cache          *cache.Service
	records        *state.Store
	checkIsolation func(context.Context) (vm.SoftnetOptions, error)
	startRelay     func(context.Context, RelayPlan) (Process, error)

	mu    sync.Mutex
	procs map[string]Process // VM helper processes by VM name
}

// SetCache attaches an optional portable cache service before this provider runs.
func (p *Provider) SetCache(service *cache.Service) { p.cache = service }

// New returns the provider for VMs in store (paths.Layout.VMs). rt may be
// nil for the real VM runtime.
func New(name string, cfg config.VZ, controllerID string, store string, rt Runtime) (*Provider, error) {
	if !filepath.IsAbs(store) {
		return nil, fmt.Errorf("VM store %q is not absolute", store)
	}
	if rt == nil {
		l, err := newLocal(store)
		if err != nil {
			return nil, err
		}
		rt = l
	}
	return &Provider{name: name, cfg: cfg, controllerID: controllerID, store: vm.Store(store), rt: rt, procs: map[string]Process{}}, nil
}

// CheckRuntime fails when this host cannot run guests: the executable that
// launches VM helpers lacks the virtualization entitlement. The daemon calls
// it at startup, so an unsigned build never accepts a job.
func (p *Provider) CheckRuntime(ctx context.Context) error {
	l, ok := p.rt.(*local)
	if !ok {
		return nil
	}
	if err := l.check(ctx); err != nil {
		return err
	}
	return CheckNested(p.cfg)
}

// CheckNested fails when the config asks for nested virtualization on a
// host whose framework cannot provide it.
func CheckNested(cfg config.VZ) error {
	if !cfg.Machine.NestedVirtualization && (cfg.Containers == nil || !cfg.Containers.Machine.NestedVirtualization) {
		return nil
	}
	ok, err := vm.NestedVirtualizationSupported()
	if err != nil {
		return err
	}
	if !ok {
		return vm.ErrNestedUnsupported
	}
	return nil
}

// MachineOptions maps typed config to the helper's options.
func MachineOptions(m config.Machine) vm.MachineOptions {
	return vm.MachineOptions{
		Display:  vm.Display{Width: m.Display.Width, Height: m.Display.Height, PPI: m.Display.PPI},
		DiskSync: m.DiskSync,
		Nested:   m.NestedVirtualization,
	}
}

// engineMachine is the container engine VM's machine options.
func (p *Provider) engineMachine() vm.MachineOptions {
	if p.cfg.Containers == nil {
		return vm.MachineOptions{}
	}
	return MachineOptions(p.cfg.Containers.Machine)
}

// Name implements provider.Provider.
func (p *Provider) Name() string { return p.name }

// Capabilities implements provider.Provider. The graphics device is always
// attached, so the headless guest keeps a display and Metal.
func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{GPU: provider.GPUParavirtualized, DesktopSession: true, DisplayTransport: "none", HostLimit: p.cfg.HostVMLimit}
}

func (p *Provider) vmDir(name string) string { return p.store.Dir(name) }

func (p *Provider) checkName(name string) error {
	if !strings.HasPrefix(name, config.NamePrefix) {
		return fmt.Errorf("%w: %q lacks the %q prefix", provider.ErrNotOwned, name, config.NamePrefix)
	}
	if strings.ContainsAny(name, "/\\ \t\n") || name == p.cfg.Baseline {
		return fmt.Errorf("%w: invalid name %q", provider.ErrNotOwned, name)
	}
	return nil
}

func (p *Provider) readMeta(name string) (provider.Metadata, bool) {
	data, err := os.ReadFile(filepath.Join(p.vmDir(name), markerFile))
	if err != nil {
		return provider.Metadata{}, false
	}
	var meta provider.Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return provider.Metadata{}, false
	}
	return meta, true
}

func (p *Provider) owns(name string) (provider.Metadata, bool) {
	meta, ok := p.readMeta(name)
	return meta, ok && meta.ControllerID == p.controllerID && strings.HasPrefix(name, config.NamePrefix)
}

// ownsGuest proves, before every guest operation, that name is a runner VM
// this controller created: prefix, valid name, and our marker. A container
// engine companion never runs the runner, and pair markers are refused
// outside the pair topology.
func (p *Provider) ownsGuest(name string) error {
	if err := p.checkName(name); err != nil {
		return err
	}
	meta, ok := p.owns(name)
	if !ok || meta.ParentName != "" || (p.cfg.Containers == nil && meta.EngineName != "") {
		return provider.ErrNotOwned
	}
	return nil
}

// output runs argv in name's guest; its stdout is at most defaultOutputLimit.
func (p *Provider) output(ctx context.Context, name string, argv []string, stdin io.Reader) ([]byte, error) {
	return p.guest(ctx, name, argv, stdin, defaultOutputLimit)
}

// guest runs argv in name's guest and returns at most limit bytes of stdout;
// more fails the call. Errors never carry guest output.
func (p *Provider) guest(ctx context.Context, name string, argv []string, stdin io.Reader, limit int) ([]byte, error) {
	b := &boundedBuffer{limit: limit}
	err := p.rt.Exec(ctx, name, argv, stdin, b)
	if b.exceeded {
		return nil, fmt.Errorf("guest %s: stdout %w of %d bytes", argv[0], ErrOutputLimit, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("guest %s: %w", argv[0], err)
	}
	return b.data, nil
}

// Create implements provider.Provider.
func (p *Provider) createVM(ctx context.Context, spec provider.Spec, wantOS string, machine vm.MachineOptions) error {
	if err := p.checkName(spec.Name); err != nil {
		return err
	}
	if spec.Baseline == "" || strings.HasPrefix(spec.Baseline, config.NamePrefix) {
		return fmt.Errorf("refusing baseline %q", spec.Baseline)
	}
	m, err := CheckBaseline(string(p.store), spec.Baseline, wantOS)
	if err != nil {
		return err
	}
	if err := machine.CheckGuest(m); err != nil {
		return fmt.Errorf("baseline %q: %w", spec.Baseline, err)
	}
	if err := p.rt.Clone(ctx, spec.Baseline, spec.Name, vm.CloneOptions{CPU: spec.CPU, MemoryMiB: spec.MemoryMB}); err != nil {
		return err
	}
	meta, err := json.Marshal(spec.Meta)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(p.vmDir(spec.Name), markerFile), meta, 0o600); err != nil {
		return fmt.Errorf("write marker: %w", err)
	}
	return nil
}

// CheckBaseline refuses a baseline in store that bivouac cannot drive: one
// without a manifest, of another OS (darwin for runners, linux for container
// engines), without a runner directory, or with a guest agent of another
// protocol version.
func CheckBaseline(store, name, wantOS string) (vm.Manifest, error) {
	m, err := vm.ReadManifest(vm.Store(store).Dir(name))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return m, fmt.Errorf("baseline %q has no bivouac manifest in %s; import it with `bivouac vz import`", name, store)
	case err != nil:
		return m, fmt.Errorf("baseline %q: %w", name, err)
	case m.OS != wantOS:
		return m, fmt.Errorf("baseline %q is a %s VM, not %s", name, m.OS, wantOS)
	case m.Guest.AgentVersion != guestagent.Version:
		return m, fmt.Errorf("baseline %q has guest agent protocol %d, this bivouac needs %d; install the matching agent and import it again", name, m.Guest.AgentVersion, guestagent.Version)
	case wantOS == "darwin" && m.Guest.RunnerDir == "":
		return m, fmt.Errorf("baseline %q records no runner directory; import it with --runner-dir", name)
	}
	return m, nil
}

// guestContract is name's guest contract, from the manifest its clone
// carries.
func (p *Provider) guestContract(name string) (vm.Guest, error) {
	m, err := vm.ReadManifest(p.vmDir(name))
	if err != nil {
		return vm.Guest{}, fmt.Errorf("guest %q manifest: %w", name, err)
	}
	return m.Guest, nil
}

// checkReleaseProxy refuses the release proxy for a guest whose image does
// not record passwordless sudo, which installing its trust needs; the
// caller then runs the job without the cache.
func (p *Provider) checkReleaseProxy(name string) error {
	guest, err := p.guestContract(name)
	if err != nil {
		return err
	}
	if !guest.Sudo {
		return errors.New("the release proxy needs passwordless sudo, which the baseline does not record")
	}
	return nil
}

// runnerDir is the runner directory name's image records.
func (p *Provider) runnerDir(name string) (string, error) {
	g, err := p.guestContract(name)
	if err == nil && g.RunnerDir == "" {
		err = fmt.Errorf("guest %q records no runner directory", name)
	}
	return g.RunnerDir, err
}

// runnerLaunch attaches input devices, the optional bootstrap share, and
// the configured machine options; the guest console is never attached.
func (p *Provider) runnerLaunch() Launch {
	return Launch{Share: p.cfg.BootstrapShare, Input: true, Machine: MachineOptions(p.cfg.Machine)}
}

// LaunchArgs is the exact argument array the VM helper receives for a
// runner guest named name, or nil for a substituted runtime.
func (p *Provider) LaunchArgs(name string) ([]string, error) {
	l, ok := p.rt.(*local)
	if !ok {
		return nil, nil
	}
	launch := p.runnerLaunch()
	if p.cfg.Containers != nil {
		launch = Launch{Softnet: &vm.SoftnetOptions{Binary: "<softnet>", Block: "<policy>"}}
	}
	return l.helperArgs(name, launch)
}

func (p *Provider) describe(name string, launch Launch) string {
	if l, ok := p.rt.(*local); ok {
		if args, err := l.helperArgs(name, launch); err == nil {
			return strings.Join(args, " ")
		}
	}
	return "vm run " + name
}

// Start implements provider.Provider.
func (p *Provider) startVM(ctx context.Context, name string, launch Launch, launchLog io.Writer) error {
	if _, ok := p.owns(name); !ok {
		return provider.ErrNotOwned
	}
	_, _ = fmt.Fprintf(launchLog, "%s bivouac: %s\n", time.Now().UTC().Format(time.RFC3339), redact.String(p.describe(name, launch)))
	// A file is handed to the helper as its own descriptor: a pipe read by
	// this process would end in SIGPIPE for the helper once the controller
	// exits. The helper writes only host-side status there. Any other writer
	// is already copied by this process, so it is bounded and redacted.
	sink := launchLog
	if _, ok := launchLog.(*os.File); !ok {
		sink = redact.NewWriter(&dropWriter{w: launchLog, remaining: launchLogLimit})
	}
	// The VM must outlive a controller restart, so it is not bound to ctx.
	proc, err := p.rt.Start(context.WithoutCancel(ctx), name, launch, sink)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.procs[name] = proc
	p.mu.Unlock()
	return nil
}

// LaunchPID returns the pid of the VM helper for name, or 0 when this
// process did not start it.
func (p *Provider) LaunchPID(name string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if proc, ok := p.procs[name]; ok {
		return proc.PID()
	}
	return 0
}

func (p *Provider) proc(name string) (Process, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	proc, ok := p.procs[name]
	return proc, ok
}

// WaitReady implements provider.Provider: the guest agent runs a command.
func (p *Provider) waitVM(ctx context.Context, name string) error {
	proc, started := p.proc(name)
	wait := 500 * time.Millisecond
	for {
		if started {
			select {
			case <-proc.Done():
				return fmt.Errorf("VM helper exited before the guest was ready: %w", proc.Err())
			default:
			}
		}
		_, err := p.output(ctx, name, []string{"true"}, nil)
		if err == nil {
			return nil
		}
		// Only an unreachable agent may still be booting. One that answered
		// and refused (such as an outdated protocol version) stays refused.
		if ctx.Err() == nil && !errors.Is(err, guestagent.ErrUnavailable) {
			return fmt.Errorf("guest agent is not ready: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, 3*time.Second)
	}
}

func (p *Provider) installGuestScript(ctx context.Context, name string) error {
	if _, err := p.output(ctx, name, []string{"tee", guestPath}, bytes.NewReader(guestScript)); err != nil {
		return fmt.Errorf("install guest script: %w", err)
	}
	if _, err := p.output(ctx, name, []string{"chmod", "0700", guestPath}, nil); err != nil {
		return fmt.Errorf("chmod guest script: %w", err)
	}
	return nil
}

// checkSession requires the guest agent, and therefore the runner it starts,
// to run in the logged-in GUI (Aqua) launchd session. Elsewhere windowed and
// GPU tests cannot reach the window server.
func (p *Provider) checkSession(ctx context.Context, name string) error {
	out, err := p.guest(ctx, name, []string{guestPath, "session"}, nil, 256)
	if err != nil {
		return fmt.Errorf("check guest launchd session: %w", err)
	}
	session := strings.TrimSpace(string(out))
	if session == "Aqua" {
		return nil
	}
	if len(session) > 32 || strings.ContainsFunc(session, func(r rune) bool { return (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') }) {
		session = "unrecognised"
	}
	return fmt.Errorf("guest agent runs in launchd session %q, not Aqua: enable automatic login for the baseline user and install the bivouac guest agent LaunchAgent", session)
}

// StartRunner implements provider.Provider. The JIT config travels on the
// guest agent's stdin channel; the agent runs inside the Aqua session.
func (p *Provider) StartRunner(ctx context.Context, name string, jit []byte) error {
	// The bootstrap returns as soon as the runner is backgrounded; a session
	// that lingers means the guest kept the agent's pipes open.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if p.cfg.Containers != nil {
		if err := p.engineHealthy(ctx, name); err != nil {
			return err
		}
	}
	// Never send the JIT config to a VM this controller cannot prove it owns.
	if err := p.ownsGuest(name); err != nil {
		return err
	}
	if err := p.installGuestHelper(ctx, name); err != nil {
		// Telemetry is optional, but never execute a partially copied binary.
		if _, cleanupErr := p.output(ctx, name, []string{"rm", "-f", guestHelper}, nil); cleanupErr != nil {
			return errors.New("remove incomplete guest helper")
		}
	}
	if p.cache != nil {
		if err := p.installCache(ctx, name); err != nil {
			p.cache.GuestUnavailable(name)
			p.cache.Revoke(name)
			// Optional caching must not strand a healthy guest. Remove a partial
			// adapter before starting the official runner on its normal paths.
			if _, cleanupErr := p.output(ctx, name, []string{"rm", "-f", "/tmp/bivouac/cache-config.json", "/tmp/bivouac-cache-preload.cjs", "/tmp/bivouac-cache-client", "/tmp/bivouac-cache-env"}, nil); cleanupErr != nil {
				return errors.New("remove incomplete guest cache adapter")
			}
		}
	}
	// Ownership is rechecked right before the config leaves the host.
	if err := p.ownsGuest(name); err != nil {
		return err
	}
	dir, err := p.runnerDir(name)
	if err != nil {
		return err
	}
	out, err := p.guest(ctx, name, []string{guestPath, "start", dir}, bytes.NewReader(jit), statusOutputLimit)
	if err != nil {
		return err
	}
	if !strings.Contains(string(out), "started") {
		return errors.New("guest bootstrap did not confirm start")
	}
	return nil
}

func (p *Provider) installCache(ctx context.Context, name string) error {
	if _, err := p.output(ctx, name, []string{"mkdir", "-p", "-m", "0700", guestDirectory}, nil); err != nil {
		return errors.New("prepare private guest cache directory")
	}
	bootstrap, err := p.cache.Issue(name)
	if err != nil {
		return err
	}
	var settings cache.Bootstrap
	if err = json.Unmarshal(bootstrap, &settings); err != nil {
		return errors.New("invalid cache bootstrap")
	}
	if settings.ReleaseProxy {
		if err := p.checkReleaseProxy(name); err != nil {
			return err
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	f, err := os.Open(exe)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	// dd writes without echoing the binary or private bootstrap back to the host.
	for _, file := range []struct {
		path  string
		input io.Reader
		mode  string
	}{{"/tmp/bivouac-cache-preload.cjs", bytes.NewReader(cache.Preload()), "0600"}, {"/tmp/bivouac-cache-client", f, "0700"}, {"/tmp/bivouac/cache-config.json", bytes.NewReader(bootstrap), "0600"}} {
		if _, err := p.output(ctx, name, []string{"/usr/bin/install", "-m", "0600", "/dev/null", file.path}, nil); err != nil {
			return errors.New("prepare private guest cache adapter")
		}
		if _, err := p.output(ctx, name, []string{"dd", "of=" + file.path, "status=none"}, file.input); err != nil {
			return errors.New("install guest cache adapter")
		}
		if _, err := p.output(ctx, name, []string{"chmod", file.mode, file.path}, nil); err != nil {
			return err
		}
	}
	if settings.ReleaseProxy {
		if _, err = p.output(ctx, name, []string{"/usr/bin/install", "-m", "0600", "/dev/null", "/tmp/bivouac-cache-ca.pem"}, nil); err != nil {
			return errors.New("prepare guest proxy trust")
		}
		if _, err = p.output(ctx, name, []string{"dd", "of=/tmp/bivouac-cache-ca.pem", "status=none"}, strings.NewReader(settings.CA)); err != nil {
			return errors.New("install guest proxy trust")
		}
		if _, err = p.output(ctx, name, []string{guestPath, "cache-setup"}, nil); err != nil {
			return errors.New("configure guest release proxy")
		}
	}
	return nil
}

// StopRunner implements provider.Provider.
func (p *Provider) StopRunner(ctx context.Context, name string) error {
	if p.cfg.Containers != nil {
		a, b, err := p.pairStatus(ctx, name)
		if err != nil {
			return err
		}
		if !a.Exists || !a.Owned || (b.Exists && !b.Owned) {
			return provider.ErrNotOwned
		}
	}
	if err := p.ownsGuest(name); err != nil {
		return err
	}
	dir, err := p.runnerDir(name)
	if err != nil {
		return err
	}
	_, err = p.output(ctx, name, []string{guestPath, "stop", dir}, nil)
	return err
}

// RunnerStatus implements provider.Provider.
func (p *Provider) RunnerStatus(ctx context.Context, name string) (provider.RunnerStatus, error) {
	if p.cfg.Containers != nil {
		if err := p.engineHealthy(ctx, name); err != nil {
			return provider.RunnerStatus{State: provider.RunnerAbsent}, err
		}
	}
	if err := p.ownsGuest(name); err != nil {
		return provider.RunnerStatus{}, err
	}
	if proc, started := p.proc(name); started {
		select {
		case <-proc.Done():
			return provider.RunnerStatus{State: provider.RunnerAbsent}, nil
		default:
		}
	}
	out, err := p.guest(ctx, name, []string{guestPath, "status"}, nil, statusOutputLimit)
	switch {
	case err == nil:
		return parseRunnerStatus(string(out))
	case errors.Is(err, ErrOutputLimit):
		return provider.RunnerStatus{}, errors.New("runner status output exceeded its bound")
	}
	return p.statusFailure(ctx, name)
}

// statusFailure classifies a failed status probe. Only a VM that is gone or
// stopped confirms the runner's absence; a failed guest command against a
// running owned VM is a guest agent transport failure, which the manager
// retries within its bounded grace. Guest output is never retained.
func (p *Provider) statusFailure(ctx context.Context, name string) (provider.RunnerStatus, error) {
	transport := func() (provider.RunnerStatus, error) {
		if errors.Is(ctx.Err(), context.Canceled) {
			return provider.RunnerStatus{}, ctx.Err()
		}
		if ctx.Err() != nil {
			return provider.RunnerStatus{}, fmt.Errorf("guest status probe: %w", provider.GuestAgentTimeout)
		}
		return provider.RunnerStatus{}, fmt.Errorf("guest status probe: %w", provider.GuestAgentUnavailable)
	}
	if ctx.Err() != nil {
		return transport()
	}
	st, err := p.statusVM(ctx, name)
	switch {
	case err != nil:
		return transport()
	case !st.Exists || !st.Running:
		return provider.RunnerStatus{State: provider.RunnerAbsent}, nil
	case !st.Owned:
		return provider.RunnerStatus{}, provider.ErrNotOwned
	}
	return transport()
}

var errRunnerStatus = errors.New("invalid runner status from guest")

func parseRunnerStatus(out string) (provider.RunnerStatus, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	fields := strings.Fields(lines[0])
	var st provider.RunnerStatus
	if len(fields) == 0 {
		return st, errRunnerStatus
	}
	switch fields[0] {
	case "absent":
		st.State = provider.RunnerAbsent
	case "exited":
		st.State = provider.RunnerExited
		if len(fields) > 1 {
			st.ExitCode, _ = strconv.Atoi(fields[1])
		}
	case "running":
		st.State = provider.RunnerRunning
	case "listening":
		st.State = provider.RunnerListening
	case "starting":
		st.State = provider.RunnerStarting
	default:
		return provider.RunnerStatus{}, errRunnerStatus
	}
	job := &provider.RunnerJob{}
	for _, line := range lines[1:] {
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "run_id":
			job.RunID, _ = strconv.ParseInt(value, 10, 64)
		case "repository":
			job.Repository = value
		case "job":
			job.Name = value
		}
	}
	owner, repo, ok := strings.Cut(job.Repository, "/")
	if job.RunID > 0 && ok && owner != "" && repo != "" && !strings.Contains(repo, "/") {
		st.Job = job
	}
	return st, nil
}

func (p *Provider) list(ctx context.Context) ([]vm.Entry, error) {
	return p.rt.List(ctx)
}

// Status implements provider.Provider.
func (p *Provider) statusVM(ctx context.Context, name string) (provider.Status, error) {
	entries, err := p.list(ctx)
	if err != nil {
		return provider.Status{}, err
	}
	for _, e := range entries {
		if e.Name != name {
			continue
		}
		meta, owned := p.owns(name)
		return provider.Status{Exists: true, Running: e.Running, Owned: owned, Meta: meta}, nil
	}
	return provider.Status{}, nil
}

// Stop implements provider.Provider.
func (p *Provider) stopVM(ctx context.Context, name string, timeout time.Duration) error {
	if _, ok := p.owns(name); !ok {
		return provider.ErrNotOwned
	}
	err := p.rt.Stop(ctx, name, max(timeout, time.Second))
	if err != nil && !absent(err) {
		if proc, ok := p.proc(name); ok {
			_ = proc.Kill()
			<-proc.Done()
			return nil
		}
		return err
	}
	if proc, ok := p.proc(name); ok {
		select {
		case <-proc.Done():
		case <-time.After(timeout + 10*time.Second):
			_ = proc.Kill()
		}
	}
	return nil
}

// Delete implements provider.Provider. It requires the prefix and our
// marker, so a baseline, a foreign VM, or another manager's clone is never
// deleted.
func (p *Provider) deleteVM(ctx context.Context, name string) error {
	if err := p.checkName(name); err != nil {
		return err
	}
	st, err := p.statusVM(ctx, name)
	if err != nil {
		return err
	}
	if !st.Exists {
		if p.cache != nil {
			p.cache.Revoke(name)
		}
		p.forget(name)
		return provider.ErrNotFound
	}
	if !st.Owned {
		return provider.ErrNotOwned
	}
	if err := p.rt.Delete(ctx, name); err != nil && !absent(err) {
		return err
	}
	p.forget(name)
	if p.cache != nil {
		p.cache.Revoke(name)
	}
	return nil
}

func (p *Provider) forget(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.procs, name)
}

// List implements provider.Provider.
func (p *Provider) listVMs(ctx context.Context) ([]provider.Owned, []provider.Foreign, error) {
	entries, err := p.list(ctx)
	if err != nil {
		return nil, nil, err
	}
	var owned []provider.Owned
	var foreign []provider.Foreign
	for _, e := range entries {
		if meta, ok := p.owns(e.Name); ok {
			owned = append(owned, provider.Owned{Name: e.Name, Running: e.Running, Meta: meta})
			continue
		}
		prefixed := strings.HasPrefix(e.Name, config.NamePrefix)
		if e.Running || prefixed {
			foreign = append(foreign, provider.Foreign{Name: e.Name, Running: e.Running, Prefixed: prefixed})
		}
	}
	return owned, foreign, nil
}
