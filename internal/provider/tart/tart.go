// Package tart is the macOS provider: disposable guests cloned from a local
// Tart baseline, run with --no-graphics, driven through the Tart guest agent
// so the runner lives in the guest's Aqua session.
package tart

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/redact"
	"github.com/GomerPiles/bivouac/internal/state"
)

//go:embed guest.sh
var guestScript []byte

// guestPath is where the bootstrap script lives inside each clone.
const guestPath = "/tmp/bivouac-guest"

// markerFile is written beside Tart's own config.json after a clone. Tart
// ignores extra files in a VM directory and deletes them with the VM.
const markerFile = "bivouac.json"

// Provider implements provider.Provider on the Tart CLI.
type Provider struct {
	name           string
	cfg            config.Tart
	controllerID   string
	home           string // Tart home holding vms/
	exec           Exec
	cache          *cache.Service
	records        *state.Store
	checkIsolation func(context.Context) (string, error)
	startRelay     func(context.Context, RelayPlan) (Process, error)

	mu    sync.Mutex
	procs map[string]Process // `tart run` processes by VM name
}

// SetCache attaches an optional portable cache service before this provider runs.
func (p *Provider) SetCache(service *cache.Service) { p.cache = service }

// New returns a Tart provider. exec may be nil for the real binary.
func New(name string, cfg config.Tart, controllerID string, exec Exec) (*Provider, error) {
	home := os.Getenv("TART_HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		home = filepath.Join(h, ".tart")
	}
	if exec == nil {
		exec = CLI{Binary: cfg.Binary, Env: []string{"TART_NO_AUTO_PRUNE=1"}}
	}
	return &Provider{name: name, cfg: cfg, controllerID: controllerID, home: home, exec: exec, procs: map[string]Process{}}, nil
}

// Name implements provider.Provider.
func (p *Provider) Name() string { return p.name }

// Capabilities implements provider.Provider. Tart's graphics device is always
// attached, so the guest keeps a display and Metal even with --no-graphics.
func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{GPU: provider.GPUParavirtualized, DesktopSession: true, DisplayTransport: "none", HostLimit: p.cfg.HostVMLimit}
}

func (p *Provider) vmDir(name string) string { return filepath.Join(p.home, "vms", name) }

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

// output runs a tart command whose stdout is at most defaultOutputLimit.
func (p *Provider) output(ctx context.Context, args []string, stdin io.Reader) ([]byte, error) {
	return output(ctx, p.exec, args, stdin, defaultOutputLimit)
}

// Create implements provider.Provider.
func (p *Provider) createVM(ctx context.Context, spec provider.Spec) error {
	if err := p.checkName(spec.Name); err != nil {
		return err
	}
	if spec.Baseline == "" || strings.HasPrefix(spec.Baseline, config.NamePrefix) {
		return fmt.Errorf("refusing baseline %q", spec.Baseline)
	}
	if _, err := p.output(ctx, []string{"clone", spec.Baseline, spec.Name}, nil); err != nil {
		return err
	}
	meta, err := json.Marshal(spec.Meta)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(p.vmDir(spec.Name), markerFile), meta, 0o600); err != nil {
		return fmt.Errorf("write marker: %w", err)
	}
	var set []string
	if spec.CPU > 0 {
		set = append(set, "--cpu", strconv.Itoa(spec.CPU))
	}
	if spec.MemoryMB > 0 {
		set = append(set, "--memory", strconv.Itoa(spec.MemoryMB))
	}
	if len(set) > 0 {
		if _, err := p.output(ctx, append([]string{"set", spec.Name}, set...), nil); err != nil {
			return err
		}
	}
	return nil
}

// RunArgs is the exact argument array `tart run` receives for name.
func (p *Provider) RunArgs(name string, extra []string) []string {
	if p.cfg.Containers != nil {
		policy, err := NetworkPolicy()
		if err != nil {
			policy = "@host,0.0.0.0/0"
		}
		return isolatedArgs(name, policy)
	}
	args := []string{"run", "--no-graphics"}
	if p.cfg.BootstrapShare != "" {
		args = append(args, "--dir=bivouac:"+p.cfg.BootstrapShare+":ro")
	}
	args = append(args, extra...)
	return append(args, name)
}

// Start implements provider.Provider.
func (p *Provider) startVM(ctx context.Context, name string, args []string, launchLog io.Writer) error {
	if _, ok := p.owns(name); !ok {
		return provider.ErrNotOwned
	}
	for _, a := range args {
		if a == "--serial" || strings.HasPrefix(a, "--serial=") {
			return errors.New("tart --serial would copy guest console output into the launch log; remove it from extra_args")
		}
	}
	_, _ = fmt.Fprintf(launchLog, "%s bivouac: tart %s\n", time.Now().UTC().Format(time.RFC3339), redact.String(strings.Join(args, " ")))
	// A file is handed to Tart as its own descriptor: a pipe read by this
	// process would end in SIGPIPE for the guest once the controller exits.
	// What Tart writes there is its own host-side status (no guest console,
	// since --serial is refused). Any other writer is already copied by this
	// process, so it is bounded and redacted.
	sink := launchLog
	if _, ok := launchLog.(*os.File); !ok {
		sink = redact.NewWriter(&dropWriter{w: launchLog, remaining: launchLogLimit})
	}
	// The VM must outlive a controller restart, so it is not bound to ctx.
	proc, err := p.exec.Start(context.WithoutCancel(ctx), args, sink)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.procs[name] = proc
	p.mu.Unlock()
	return nil
}

// LaunchPID returns the pid of the `tart run` process for name, or 0 when
// this process did not start it.
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

// WaitReady implements provider.Provider: the guest agent answers `tart exec`.
func (p *Provider) waitVM(ctx context.Context, name string) error {
	proc, started := p.proc(name)
	wait := 500 * time.Millisecond
	for {
		if started {
			select {
			case <-proc.Done():
				return fmt.Errorf("tart run exited before the guest was ready: %w", proc.Err())
			default:
			}
		}
		if _, err := p.output(ctx, []string{"exec", name, "true"}, nil); err == nil {
			return nil
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
	if _, err := p.output(ctx, []string{"exec", "-i", name, "tee", guestPath}, bytes.NewReader(guestScript)); err != nil {
		return fmt.Errorf("install guest script: %w", err)
	}
	if _, err := p.output(ctx, []string{"exec", name, "chmod", "0700", guestPath}, nil); err != nil {
		return fmt.Errorf("chmod guest script: %w", err)
	}
	return nil
}

// checkSession requires the guest agent, and therefore the runner it starts,
// to run in the logged-in GUI (Aqua) launchd session. Elsewhere windowed and
// GPU tests cannot reach the window server.
func (p *Provider) checkSession(ctx context.Context, name string) error {
	out, err := output(ctx, p.exec, []string{"exec", name, guestPath, "session"}, nil, 256)
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
	return fmt.Errorf("guest agent runs in launchd session %q, not Aqua: enable automatic login for the baseline user and run the Tart guest agent as a LaunchAgent in that GUI session", session)
}

// StartRunner implements provider.Provider. The JIT config travels on the
// guest agent's stdin channel; `tart exec` runs inside the Aqua session.
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
		if _, cleanupErr := p.output(ctx, []string{"exec", name, "rm", "-f", guestHelper}, nil); cleanupErr != nil {
			return errors.New("remove incomplete guest helper")
		}
	}
	if p.cache != nil {
		if err := p.installCache(ctx, name); err != nil {
			p.cache.GuestUnavailable(name)
			p.cache.Revoke(name)
			// Optional caching must not strand a healthy guest. Remove a partial
			// adapter before starting the official runner on its normal paths.
			if _, cleanupErr := p.output(ctx, []string{"exec", name, "rm", "-f", "/tmp/bivouac/cache-config.json", "/tmp/bivouac-cache-preload.cjs", "/tmp/bivouac-cache-client", "/tmp/bivouac-cache-env"}, nil); cleanupErr != nil {
				return errors.New("remove incomplete guest cache adapter")
			}
		}
	}
	// Ownership is rechecked right before the config leaves the host.
	if err := p.ownsGuest(name); err != nil {
		return err
	}
	out, err := output(ctx, p.exec, []string{"exec", "-i", name, guestPath, "start", p.cfg.RunnerDir}, bytes.NewReader(jit), statusOutputLimit)
	if err != nil {
		return err
	}
	if !strings.Contains(string(out), "started") {
		return errors.New("guest bootstrap did not confirm start")
	}
	return nil
}

func (p *Provider) installCache(ctx context.Context, name string) error {
	if _, err := p.output(ctx, []string{"exec", name, "mkdir", "-p", "-m", "0700", guestDirectory}, nil); err != nil {
		return errors.New("prepare private guest cache directory")
	}
	bootstrap, err := p.cache.Issue(name)
	if err != nil {
		return err
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
		if _, err := p.output(ctx, []string{"exec", name, "/usr/bin/install", "-m", "0600", "/dev/null", file.path}, nil); err != nil {
			return errors.New("prepare private guest cache adapter")
		}
		if _, err := p.output(ctx, []string{"exec", "-i", name, "dd", "of=" + file.path, "status=none"}, file.input); err != nil {
			return errors.New("install guest cache adapter")
		}
		if _, err := p.output(ctx, []string{"exec", name, "chmod", file.mode, file.path}, nil); err != nil {
			return err
		}
	}
	var settings cache.Bootstrap
	if err = json.Unmarshal(bootstrap, &settings); err != nil {
		return errors.New("invalid cache bootstrap")
	}
	if settings.ReleaseProxy {
		if _, err = p.output(ctx, []string{"exec", name, "/usr/bin/install", "-m", "0600", "/dev/null", "/tmp/bivouac-cache-ca.pem"}, nil); err != nil {
			return errors.New("prepare guest proxy trust")
		}
		if _, err = p.output(ctx, []string{"exec", "-i", name, "dd", "of=/tmp/bivouac-cache-ca.pem", "status=none"}, strings.NewReader(settings.CA)); err != nil {
			return errors.New("install guest proxy trust")
		}
		if _, err = p.output(ctx, []string{"exec", name, guestPath, "cache-setup"}, nil); err != nil {
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
	_, err := p.output(ctx, []string{"exec", name, guestPath, "stop", p.cfg.RunnerDir}, nil)
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
	out, err := output(ctx, p.exec, []string{"exec", name, guestPath, "status"}, nil, statusOutputLimit)
	switch {
	case err == nil:
		return parseRunnerStatus(string(out))
	case errors.Is(err, ErrOutputLimit):
		return provider.RunnerStatus{}, errors.New("runner status output exceeded its bound")
	}
	return p.statusFailure(ctx, name)
}

// statusFailure classifies a failed status probe. Only a VM that is gone or
// stopped confirms the runner's absence; a failed `tart exec` against a
// running owned VM is a guest agent transport failure, which the manager
// retries within its bounded grace. Guest output is never retained.
func (p *Provider) statusFailure(ctx context.Context, name string) (provider.RunnerStatus, error) {
	transport := func() (provider.RunnerStatus, error) {
		if errors.Is(ctx.Err(), context.Canceled) {
			return provider.RunnerStatus{}, ctx.Err()
		}
		if ctx.Err() != nil {
			return provider.RunnerStatus{}, fmt.Errorf("tart status probe: %w", provider.GuestAgentTimeout)
		}
		return provider.RunnerStatus{}, fmt.Errorf("tart status probe: %w", provider.GuestAgentUnavailable)
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

type listEntry struct {
	Name    string `json:"Name"`
	Source  string `json:"Source"`
	Running bool   `json:"Running"`
}

func (p *Provider) list(ctx context.Context) ([]listEntry, error) {
	out, err := output(ctx, p.exec, []string{"list", "--source", "local", "--format", "json"}, nil, listOutputLimit)
	if err != nil {
		return nil, err
	}
	var entries []listEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, fmt.Errorf("parse tart list: %w", err)
	}
	return entries, nil
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
	secs := max(int(timeout.Seconds()), 1)
	_, err := p.output(ctx, []string{"stop", name, "--timeout", strconv.Itoa(secs)}, nil)
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
	if _, err := p.output(ctx, []string{"delete", name}, nil); err != nil && !absent(err) {
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
