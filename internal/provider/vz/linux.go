package vz

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/diag"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/linuxguest"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/vm"
)

// HostLimitExempt proves a guest cannot consume an Apple macOS guest slot.
// Unknown/corrupt manifests, including not-yet-created clones, count as slots.
func (p *Provider) HostLimitExempt(name string) bool {
	m, err := vm.ReadManifest(p.vmDir(name))
	return err == nil && m.OS == "linux"
}

// ValidateRetained freezes guest OS using the clone, never a replaceable baseline.
func (p *Provider) ValidateRetained(name string) error {
	if err := p.checkName(name); err != nil {
		return err
	}
	info, err := os.Lstat(p.vmDir(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("retained guest directory is unavailable")
	}
	m, err := vm.ReadManifest(p.vmDir(name))
	if err != nil {
		return errors.New("retained guest manifest is unavailable; restore its original manifest before retrying this record")
	}
	if m.OS != p.runner.OS {
		return errors.New("cannot change guest_os with retained guests; finish cleanup first")
	}
	return nil
}

func (p *Provider) linuxHealthy(ctx context.Context, name string) error {
	if err := p.runnerIsolation(name); err != nil {
		return err
	}
	if err := p.ValidateRetained(name); err != nil {
		return err
	}
	st, err := p.statusVM(ctx, name)
	if err != nil {
		return err
	}
	if !st.Exists || !st.Running || !st.Owned {
		return errors.New("isolated Linux guest unavailable")
	}
	return nil
}

// LinuxExecutor uses the caller's lifetime and bounds transport output. The
// caller proves ownership: runners use durable records; factories use journals.
type LinuxExecutor func(context.Context, []string, io.Reader, int) ([]byte, error)

func boundedLinuxExec(exec LinuxExecutor) LinuxExecutor {
	return func(ctx context.Context, args []string, in io.Reader, limit int) ([]byte, error) {
		out, err := exec(ctx, args, in, limit)
		if len(out) > limit {
			return nil, ErrOutputLimit
		}
		return out, err
	}
}

// WaitAgent is shared by runner readiness and the disposable factory gate.
func WaitAgent(ctx context.Context, exec LinuxExecutor, done <-chan struct{}, exitError func() error) error {
	exec = boundedLinuxExec(exec)
	wait := 500 * time.Millisecond
	for {
		select {
		case <-done:
			if err := exitError(); err != nil {
				return fmt.Errorf("VM helper exited before guest readiness: %w", err)
			}
			return errors.New("VM helper stopped before guest readiness")
		default:
		}
		_, err := exec(ctx, []string{"true"}, nil, 128)
		if err == nil {
			return nil
		}
		if ctx.Err() == nil && !errors.Is(err, guestagent.ErrUnavailable) {
			return fmt.Errorf("guest agent refused readiness: %w", err)
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		wait = min(wait*2, 3*time.Second)
	}
}
func checkLinuxIdentity(ctx context.Context, exec LinuxExecutor) error {
	for _, probe := range []struct {
		args []string
		want string
	}{
		{[]string{"/usr/bin/uname", "-s"}, "Linux"}, {[]string{"/usr/bin/uname", "-m"}, "aarch64"},
	} {
		out, err := exec(ctx, probe.args, nil, 128)
		if err != nil || strings.TrimSpace(string(out)) != probe.want {
			return errors.New("linux guest identity differs from Linux/aarch64")
		}
	}
	out, err := exec(ctx, []string{"/usr/bin/id", "-u"}, nil, 128)
	uid, parseErr := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32)
	if err != nil || parseErr != nil || uid == 0 {
		return errors.New("linux guest agent must use a non-root user")
	}
	return nil
}

// PrepareLinuxGuest verifies identity, pins the helper before execution and
// validates VZ DHCP provenance without sending JIT or granting cache access.
func PrepareLinuxGuest(ctx context.Context, exec LinuxExecutor, cfg linuxguest.GuestConfig, want string) error {
	exec = boundedLinuxExec(exec)
	if cfg.Profile != linuxguest.VZ || cfg.RunnerDir != "/opt/actions-runner" {
		return errors.New("invalid VZ Linux guest contract")
	}
	if err := checkLinuxIdentity(ctx, exec); err != nil {
		return err
	}
	probe, err := exec(ctx, []string{"/bin/sh", "-s"}, strings.NewReader(linuxguest.PreparedHelperProbe), 256)
	if err != nil {
		return errors.New("verify prepared Linux helper")
	}
	if !linuxguest.HelperMatches(probe, want) {
		return errors.New("prepared Linux helper differs; rebuild the baseline with the selected helper")
	}
	input, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	out, err := exec(ctx, []string{linuxguest.PreparedHelper, "guest", "linux", "prepare"}, bytes.NewReader(input), 4096)
	if err != nil {
		return err
	}
	_, err = linuxguest.DecodeGuestPreparation(out, cfg, true)
	return err
}
func (p *Provider) prepareLinux(ctx context.Context, name string) error {
	if err := p.linuxHealthy(ctx, name); err != nil {
		return err
	}
	dir, err := p.runnerDir(name)
	if err != nil {
		return err
	}
	if err := p.runner.CheckHelper(); err != nil {
		return err
	}
	want, err := linuxguest.HelperSHA256(p.runner.Helper)
	if err != nil {
		return err
	}
	exec := func(ctx context.Context, args []string, in io.Reader, limit int) ([]byte, error) {
		if err := p.linuxHealthy(ctx, name); err != nil {
			return nil, err
		}
		return p.guest(ctx, name, args, in, limit)
	}
	cfg := linuxguest.GuestConfig{Profile: linuxguest.VZ, Name: name, ControllerID: p.controllerID, RunnerDir: dir}
	return p.startupStage(name, "guest_prepare", func() error { return PrepareLinuxGuest(ctx, exec, cfg, want) })
}

// CheckLinuxFactoryGate adds capture-specific checks after ordinary readiness.
func CheckLinuxFactoryGate(ctx context.Context, exec LinuxExecutor, cfg linuxguest.GuestConfig, helper string, diskBytes int64) error {
	exec = boundedLinuxExec(exec)
	if err := PrepareLinuxGuest(ctx, exec, cfg, helper); err != nil {
		return err
	}
	if _, err := exec(ctx, []string{"/usr/bin/test", "-f", "/etc/cloud/cloud-init.disabled"}, nil, 128); err != nil {
		return errors.New("cloud-init disabled marker is missing")
	}
	out, err := exec(ctx, []string{"/usr/bin/stat", "-f", "-c", "%S %b", "/"}, nil, 128)
	if err != nil {
		return errors.New("cannot verify root filesystem growth")
	}
	fields := strings.Fields(string(out))
	if len(fields) != 2 {
		return errors.New("invalid root filesystem geometry")
	}
	block, e1 := strconv.ParseUint(fields[0], 10, 64)
	count, e2 := strconv.ParseUint(fields[1], 10, 64)
	if e1 != nil || e2 != nil || diskBytes <= 0 || block == 0 || block > 1<<20 || count > uint64(diskBytes)/block || block*count < uint64(diskBytes)*9/10 {
		return errors.New("root filesystem did not grow to 90 percent of disk")
	}
	return nil
}

func (p *Provider) linuxCommand(ctx context.Context, name, mode string, input io.Reader, limit int) ([]byte, error) {
	switch mode {
	case "seed-jit", "launch", "status", "cancel", "diagnostics", "cache-setup", "cache-remove":
	default:
		return nil, errors.New("invalid fixed Linux guest operation")
	}
	if err := p.linuxHealthy(ctx, name); err != nil {
		return nil, err
	}
	return p.guest(ctx, name, []string{linuxguest.RuntimeHelper, "guest", "linux", mode}, input, limit)
}

func (p *Provider) startLinuxRunner(ctx context.Context, name string, jit []byte) error {
	if len(jit) == 0 || len(jit) > 128<<10 {
		return errors.New("invalid bounded JIT input")
	}
	if p.cache != nil {
		err := p.startupStage(name, "cache_setup", func() error { return p.installLinuxCache(ctx, name) })
		if err != nil {
			p.cache.GuestUnavailable(name)
			p.cache.Revoke(name)
			// No JIT may follow uncertain adapter removal. Exit success from the
			// fixed helper confirms removal; it never echoes private bootstrap bytes.
			if _, err := p.linuxCommand(ctx, name, "cache-remove", nil, statusOutputLimit); err != nil {
				return errors.New("remove incomplete Linux guest cache adapter")
			}
		}
	}
	if err := p.startupStage(name, "jit_delivery", func() error {
		_, err := p.linuxCommand(ctx, name, "seed-jit", bytes.NewReader(jit), statusOutputLimit)
		return err
	}); err != nil {
		return err
	}
	return p.startupStage(name, "listener_launch", func() error {
		_, err := p.linuxCommand(ctx, name, "launch", nil, statusOutputLimit)
		return err
	})
}

func (p *Provider) linuxRunnerStatus(ctx context.Context, name string) (provider.RunnerStatus, error) {
	st, err := p.statusVM(ctx, name)
	if err != nil {
		return provider.RunnerStatus{}, err
	}
	if !st.Exists || !st.Running {
		return provider.RunnerStatus{State: provider.RunnerAbsent}, nil
	}
	data, err := p.linuxCommand(ctx, name, "status", nil, statusOutputLimit)
	if err != nil {
		if errors.Is(err, ErrOutputLimit) {
			return provider.RunnerStatus{}, errors.New("linux status exceeds bound")
		}
		if healthyErr := p.linuxHealthy(ctx, name); healthyErr != nil {
			return provider.RunnerStatus{}, healthyErr
		}
		return p.statusFailure(ctx, name)
	}
	var result provider.RunnerStatus
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || d.Decode(new(any)) != io.EOF {
		return provider.RunnerStatus{}, errors.New("invalid bounded Linux runner status")
	}
	switch result.State {
	case provider.RunnerAbsent, provider.RunnerStarting, provider.RunnerListening, provider.RunnerRunning, provider.RunnerExited:
	default:
		return provider.RunnerStatus{}, errors.New("unknown Linux runner state")
	}
	if result.ExitCode < -1 || result.ExitCode > 255 {
		return provider.RunnerStatus{}, errors.New("invalid Linux runner exit code")
	}
	if job := result.Job; job != nil {
		owner, repo, ok := strings.Cut(job.Repository, "/")
		if job.RunID < 1 || len(job.Repository)+len(job.Name) > 512 || strings.ContainsAny(job.Repository+job.Name, "\r\n\x00") || !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
			return provider.RunnerStatus{}, errors.New("invalid Linux runner job identity")
		}
	}
	return result, nil
}

func (p *Provider) linuxDiagnostics(ctx context.Context, name, dir string) error {
	data, err := p.linuxCommand(ctx, name, "diagnostics", nil, 45<<20)
	if err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) > 32<<20 {
		return errors.New("invalid bounded Linux diagnostics")
	}
	f, err := os.CreateTemp("", "bivouac-diagnostics-*.zip")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	_, err = f.Write(decoded)
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return diag.ExtractGuestArchive(f.Name(), dir)
}

func (p *Provider) installLinuxCache(ctx context.Context, name string) error {
	if err := p.linuxHealthy(ctx, name); err != nil {
		return err
	}
	// The runtime helper is the prepared helper pinned at readiness. Adoption
	// never attaches another endpoint or needs the selected host helper file.
	bootstrap, err := p.attachCacheEndpoint(ctx, name, linuxguest.RuntimeHelper)
	if err != nil {
		return err
	}
	defer clear(bootstrap)
	_, err = p.linuxCommand(ctx, name, "cache-setup", bytes.NewReader(bootstrap), statusOutputLimit)
	return err
}
