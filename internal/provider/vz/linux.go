package vz

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/diag"
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

func (p *Provider) checkLinuxIdentity(ctx context.Context, name string) error {
	for _, probe := range []struct {
		args []string
		want string
	}{
		{[]string{"/usr/bin/uname", "-s"}, "Linux"},
		{[]string{"/usr/bin/uname", "-m"}, "aarch64"},
	} {
		out, err := p.guest(ctx, name, probe.args, nil, 128)
		if err != nil || strings.TrimSpace(string(out)) != probe.want {
			return errors.New("linux guest identity differs from Linux/aarch64")
		}
	}
	out, err := p.guest(ctx, name, []string{"/usr/bin/id", "-u"}, nil, 128)
	uid, parseErr := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32)
	if err != nil || parseErr != nil || uid == 0 {
		return errors.New("linux guest agent must use a non-root user")
	}
	return nil
}

func (p *Provider) prepareLinux(ctx context.Context, name string) error {
	if err := p.linuxHealthy(ctx, name); err != nil {
		return err
	}
	if err := p.checkLinuxIdentity(ctx, name); err != nil {
		return err
	}
	dir, err := p.runnerDir(name)
	if err != nil {
		return err
	}
	if dir != "/opt/actions-runner" {
		return errors.New("linux baseline requires /opt/actions-runner")
	}
	if err := p.runner.CheckHelper(); err != nil {
		return err
	}
	want, err := linuxguest.HelperSHA256(p.runner.Helper)
	if err != nil {
		return err
	}
	// Probe only fixed root-owned/no-link paths. No image executable runs until
	// its exact hash matches the selected host helper; VZ has no upload fallback.
	probe, err := p.guest(ctx, name, []string{"/bin/sh", "-s"}, strings.NewReader(linuxguest.PreparedHelperProbe), 256)
	if err != nil {
		return errors.New("verify prepared Linux helper")
	}
	if !linuxguest.HelperMatches(probe, want) {
		return errors.New("prepared Linux helper differs; rebuild the baseline with the selected helper")
	}
	cfg := linuxguest.GuestConfig{Profile: linuxguest.VZ, Name: name, ControllerID: p.controllerID, RunnerDir: dir}
	input, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := p.linuxHealthy(ctx, name); err != nil {
		return err
	}
	return p.startupStage(name, "guest_prepare", func() error {
		out, err := p.guest(ctx, name, []string{linuxguest.PreparedHelper, "guest", "linux", "prepare"}, bytes.NewReader(input), 4096)
		if err != nil {
			return err
		}
		_, err = linuxguest.DecodeGuestPreparation(out, cfg, true)
		return err
	})
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
	guest, err := p.guestContract(name)
	if err != nil {
		return err
	}
	// The runtime helper is the prepared helper pinned at readiness. Adoption
	// never attaches another endpoint or needs the selected host helper file.
	bootstrap, err := p.attachCacheEndpoint(ctx, name, linuxguest.RuntimeHelper)
	if err != nil {
		return err
	}
	defer clear(bootstrap)
	var settings cache.Bootstrap
	if json.Unmarshal(bootstrap, &settings) != nil {
		return errors.New("invalid cache bootstrap")
	}
	if settings.ReleaseProxy && !guest.Sudo {
		settings.ReleaseProxy = false // archive caching requires no guest privilege
		ordinary, err := json.Marshal(settings)
		if err != nil {
			return errors.New("prepare archive-only cache bootstrap")
		}
		defer clear(ordinary)
		bootstrap = ordinary
	}
	_, err = p.linuxCommand(ctx, name, "cache-setup", bytes.NewReader(bootstrap), statusOutputLimit)
	return err
}
