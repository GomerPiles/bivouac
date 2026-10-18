package crosvm

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/appsandbox"
	"net"
)

type SSHOptions struct {
	StateDir, Helper, Key, User string
	RequirePrepared             bool
}
type SSHGuest struct {
	opts         SSHOptions
	ssh, scp     string
	commands     guestCommands
	helperSHA256 string
	cache        *cache.Service
}

func (g *SSHGuest) SetCache(service *cache.Service) { g.cache = service }

// PrepareCache uses an existing verified guest binding; no runner credential
// is involved. StartRunner falls back only after removing a partial adapter.
func (g *SSHGuest) PrepareCache(ctx context.Context, r Record) error {
	if g.cache == nil {
		return nil
	}
	bootstrap, err := g.cache.AttachSSH(ctx, r.Name, cache.SSHBinding{Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(r.SSHPort)), User: g.opts.User, KeyFile: g.opts.Key, KnownHosts: filepath.Join(g.opts.StateDir, r.Meta.InstanceID+".known_hosts")})
	if err != nil {
		return err
	}
	defer clear(bootstrap)
	_, err = g.command(ctx, r, "cache-setup", bootstrap)
	return err
}

func NewSSHGuest(opts SSHOptions) (*SSHGuest, error) {
	if !filepath.IsAbs(opts.StateDir) || !filepath.IsAbs(opts.Helper) || !identifier(opts.User, 32) {
		return nil, errors.New("invalid Linux SSH guest options")
	}
	ssh, scp, key, err := appsandbox.WindowsTransportPaths()
	if err != nil {
		return nil, err
	}
	if opts.Key == "" {
		opts.Key = key
	}
	if !filepath.IsAbs(opts.Key) {
		return nil, errors.New("linux SSH key path must be absolute")
	}
	keyInfo, err := os.Stat(opts.Key)
	if err != nil || !keyInfo.Mode().IsRegular() {
		return nil, errors.New("dedicated Linux guest SSH key is unavailable")
	}
	helper, err := elf.Open(opts.Helper)
	if err != nil {
		return nil, errors.New("linux helper is not a readable ELF binary")
	}
	defer func() { _ = helper.Close() }()
	if helper.Class != elf.ELFCLASS64 || helper.Machine != elf.EM_X86_64 || helper.Type != elf.ET_EXEC {
		return nil, errors.New("linux helper must be the matching static Linux/amd64 executable")
	}
	for _, p := range helper.Progs {
		if p.Type == elf.PT_INTERP {
			return nil, errors.New("linux helper must not require a dynamic loader")
		}
	}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.Open(opts.Helper)
	if err != nil {
		return nil, errors.New("cannot fingerprint Linux helper")
	}
	h := sha256.New()
	n, readErr := io.Copy(h, io.LimitReader(f, 128<<20+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || n > 128<<20 {
		return nil, errors.New("linux helper fingerprint exceeds bound or is unreadable")
	}
	return &SSHGuest{opts: opts, ssh: ssh, scp: scp, commands: appsandbox.NativeCommands{}, helperSHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// Forget removes the instance's pinned host key once its VM is deleted.
func (g *SSHGuest) Forget(instanceID string) error {
	return ForgetHostKeys(g.opts.StateDir, instanceID)
}

// ForgetHostKeys removes the per-instance known_hosts files under stateDir.
func ForgetHostKeys(stateDir, instanceID string) error {
	if !validID(instanceID) {
		return provider.ErrNotOwned
	}
	for _, name := range []string{instanceID + ".known_hosts", instanceID + ".known_hosts.old"} {
		if err := os.Remove(filepath.Join(stateDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (g *SSHGuest) arguments(r Record, scp bool) ([]string, error) {
	id := r.Meta.InstanceID
	if len(id) != 8 || !strings.HasPrefix(r.Name, "bivouac-") || r.SSHPort < 1024 || r.SSHPort > 65535 {
		return nil, provider.ErrNotOwned
	}
	file := filepath.Join(g.opts.StateDir, id+".known_hosts")
	strict := "yes"
	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		strict = "accept-new"
	} else if err != nil {
		return nil, err
	}
	flag := "-p"
	if scp {
		flag = "-P"
	}
	return []string{"-F", "NUL", flag, strconv.Itoa(r.SSHPort), "-i", g.opts.Key, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
		"-o", "GlobalKnownHostsFile=NUL", "-o", "UserKnownHostsFile=" + file, "-o", "StrictHostKeyChecking=" + strict, "-o", "ConnectTimeout=10"}, nil
}
func (g *SSHGuest) command(ctx context.Context, r Record, mode string, input []byte) ([]byte, error) {
	switch mode {
	case "image-identity", "boot-report", "seed-jit", "launch", "status", "cancel", "diagnostics", "cache-setup", "cache-remove":
	default:
		return nil, errors.New("invalid fixed Linux guest operation")
	}
	args, err := g.arguments(r, false)
	if err != nil {
		return nil, err
	}
	args = append(args, g.opts.User+"@127.0.0.1", runtimeHelper, "guest", "linux", mode)
	if input != nil {
		return g.commands.Input(ctx, g.ssh, args, input)
	}
	limit := 1 << 20
	if mode == "diagnostics" {
		limit = 45 << 20
	}
	return g.commands.OutputLimit(ctx, g.ssh, args, limit)
}

// Probe fixed root-owned paths without executing an unverified image helper.
// No data is interpolated into shell source; this fixed script travels on stdin.
const preparedHelperProbe = `set -eu
for p in / /usr /usr/local /usr/local/libexec /usr/local/libexec/bivouac-guest; do
 if [ ! -e "$p" ]; then printf 'absent\n';exit 0;fi
 if [ -L "$p" ]; then printf 'untrusted\n';exit 0;fi
 owner=$(/usr/bin/stat -c %u -- "$p")
 mode=$(/usr/bin/stat -c %a -- "$p")
 if [ "$owner" != 0 ] || [ "$((0$mode & 0022))" != 0 ]; then printf 'untrusted\n';exit 0;fi
done
if [ ! -f /usr/local/libexec/bivouac-guest ] || [ ! -x /usr/local/libexec/bivouac-guest ]; then printf 'untrusted\n';exit 0;fi
exec /usr/bin/sha256sum -- /usr/local/libexec/bivouac-guest
`

func helperMatches(b []byte, want string) bool {
	return digest(want) && preparedHelperFingerprint(b) == want
}

func preparedHelperFingerprint(b []byte) string {
	if len(b) > 256 {
		return ""
	}
	hash, path, ok := strings.Cut(strings.TrimSpace(string(b)), "  ")
	if !ok || !digest(hash) || path != preparedHelper {
		return ""
	}
	return hash
}
func (g *SSHGuest) Ready(ctx context.Context, r Record) error {
	return g.ready(ctx, r, g.opts.RequirePrepared)
}
func (g *SSHGuest) ready(ctx context.Context, r Record, preparedOnly bool) (result error) {
	started := time.Now()
	reused := false
	defer func() { logStartup(r.Name, "bootstrap", started, result, "helper_reused", reused) }()
	args, err := g.arguments(r, false)
	if err != nil {
		return err
	}
	probeStart := time.Now()
	args = append(args, g.opts.User+"@127.0.0.1", "/bin/sh", "-s")
	probe, err := g.commands.Input(ctx, g.ssh, args, []byte(preparedHelperProbe))
	logStartup(r.Name, "helper_check", probeStart, err)
	if err != nil {
		return err
	}
	helperPath := "./bivouac-guest"
	if helperMatches(probe, g.helperSHA256) {
		helperPath = preparedHelper
		reused = true
	} else {
		if preparedOnly {
			return errors.New("prepared image helper reuse was not proven")
		}
		if preparedHelperFingerprint(probe) != "" {
			slog.Warn("prepared Linux helper differs; uploading selected helper", "instance", r.Name)
		}
		stageStart := time.Now()
		args, err = g.arguments(r, true)
		if err != nil {
			return err
		}
		args = append(args, g.opts.Helper, g.opts.User+"@127.0.0.1:bivouac-guest")
		_, err = g.commands.Output(ctx, g.scp, args)
		logStartup(r.Name, "helper_upload", stageStart, err)
		if err != nil {
			return err
		}
		args, err = g.arguments(r, false)
		if err != nil {
			return err
		}
		args = append(args, g.opts.User+"@127.0.0.1", "/usr/bin/chmod", "700", "bivouac-guest")
		if _, err = g.commands.Output(ctx, g.ssh, args); err != nil {
			return err
		}
	}
	cfg := GuestConfig{Name: r.Name, ControllerID: r.Meta.ControllerID, RunnerDir: "/opt/actions-runner", GPU: r.GPU}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	args, err = g.arguments(r, false)
	if err != nil {
		return err
	}
	args = append(args, g.opts.User+"@127.0.0.1", helperPath, "guest", "linux", "prepare")
	stageStart := time.Now()
	data, err = g.commands.Input(ctx, g.ssh, args, data)
	if err != nil {
		logStartup(r.Name, "guest_prepare", stageStart, err)
		return err
	}
	prepared, err := decodeGuestPreparation(data, cfg, preparedOnly)
	logStartup(r.Name, "guest_prepare", stageStart, err)
	if err != nil {
		return err
	}
	logStartup(r.Name, "guest_prepare_details", stageStart, nil, "dns_ms", prepared.DNSMS, "helper_install_ms", prepared.HelperInstallMS, "guest_total_ms", prepared.TotalMS, "dns_reused", prepared.DNSReused, "dns_profile_changed", prepared.DNSProfileChanged, "dns_resolver_changed", prepared.DNSResolverChanged)
	return nil
}
func (g *SSHGuest) StartRunner(ctx context.Context, r Record, jit []byte) error {
	if len(jit) == 0 || len(jit) > 128<<10 {
		return errors.New("invalid bounded JIT input")
	}
	if g.cache != nil {
		stageStarted := time.Now()
		cacheErr := g.PrepareCache(ctx, r)
		logStartup(r.Name, "cache_setup", stageStarted, cacheErr)
		if cacheErr != nil {
			g.cache.GuestUnavailable(r.Name)
			g.cache.Revoke(r.Name)
			if _, err := g.command(ctx, r, "cache-remove", nil); err != nil {
				return errors.New("remove incomplete Linux guest cache adapter")
			}
		}
	}
	stageStarted := time.Now()
	_, seedErr := g.command(ctx, r, "seed-jit", jit)
	logStartup(r.Name, "jit_delivery", stageStarted, seedErr)
	if err := seedErr; err != nil {
		return err
	}
	stageStarted = time.Now()
	_, err := g.command(ctx, r, "launch", nil)
	logStartup(r.Name, "listener_launch", stageStarted, err)
	return err
}
func (g *SSHGuest) StopRunner(ctx context.Context, r Record) error {
	_, err := g.command(ctx, r, "cancel", nil)
	return err
}
func (g *SSHGuest) RunnerStatus(ctx context.Context, r Record) (provider.RunnerStatus, error) {
	data, err := g.command(ctx, r, "status", nil)
	if err != nil {
		return provider.RunnerStatus{}, err
	}
	var result provider.RunnerStatus
	if json.Unmarshal(data, &result) != nil {
		return result, errors.New("invalid bounded Linux runner status")
	}
	switch result.State {
	case provider.RunnerAbsent, provider.RunnerStarting, provider.RunnerListening, provider.RunnerRunning, provider.RunnerExited:
		return result, nil
	}
	return provider.RunnerStatus{}, errors.New("unknown Linux runner state")
}
func (g *SSHGuest) CollectDiagnostics(ctx context.Context, r Record, destination string) error {
	data, err := g.command(ctx, r, "diagnostics", nil)
	if err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) > 32<<20 {
		return errors.New("invalid bounded Linux diagnostic stream")
	}
	dir, err := appsandbox.PrivateGuestDirectory(g.opts.StateDir)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "diagnostics.zip")
	defer func() { _ = os.Remove(path); _ = os.Remove(dir) }()
	if err := os.WriteFile(path, decoded, 0o600); err != nil {
		return err
	}
	return appsandbox.ExtractDiagnostics(path, destination)
}

// ExercisePreparedImage is an explicit credential-free factory trial, never a
// production readiness step. Its caller must still prove current native ownership.
func (g *SSHGuest) prepareImage(ctx context.Context, r Record) error {
	b, err := g.command(ctx, r, "image-identity", nil)
	if err != nil {
		return err
	}
	var cfg GuestConfig
	if len(b) > 4096 || json.Unmarshal(b, &cfg) != nil || cfg.Name != r.Name || cfg.ControllerID != r.Meta.ControllerID || len(cfg.BootID) != 36 {
		return errors.New("image trial identity differs")
	}
	request := ImagePreparationRequest{Name: cfg.Name, ControllerID: cfg.ControllerID, BootID: cfg.BootID, HelperSHA256: g.helperSHA256}
	input, err := json.Marshal(request)
	if err != nil {
		return err
	}
	args, err := g.arguments(r, false)
	if err != nil {
		return err
	}
	args = append(args, g.opts.User+"@127.0.0.1", "/usr/bin/sudo", "-n", runtimeHelper, "guest", "linux", "prepare-image")
	b, err = g.commands.Input(ctx, g.ssh, args, input)
	if err != nil {
		return err
	}
	var report PreparedLinuxImage
	if len(b) <= 4096 && json.Unmarshal(b, &report) == nil && report.FailedStage > 0 && report.FailedStage <= 17 {
		return fmt.Errorf("image preparation refused at stage %d", report.FailedStage)
	}
	if len(b) > 4096 || json.Unmarshal(b, &report) != nil || report.HelperSHA256 != g.helperSHA256 || !report.RunnerUnconfigured || !report.DNSPrepared || !report.MachineIDCleared || !report.SSHHostKeysRemoved {
		return errors.New("image trial sanitation was not proven")
	}
	return nil
}
func (g *SSHGuest) ExercisePreparedImage(ctx context.Context, r Record) error {
	if err := g.prepareImage(ctx, r); err != nil {
		return err
	}
	// Same-boot exercise only; publication uses a separate clean capture path.
	return g.ready(ctx, r, true)
}

// PrepareImageAndShutdown is factory-only: it removes bootstrap state before
// dispatching a nonblocking clean guest shutdown. The caller must independently
// confirm natural native exit and absence before reading the disk.
func (g *SSHGuest) PrepareImageAndShutdown(ctx context.Context, r Record) error {
	if err := g.prepareImage(ctx, r); err != nil {
		return err
	}
	args, err := g.arguments(r, false)
	if err != nil {
		return err
	}
	args = append(args, g.opts.User+"@127.0.0.1", "/usr/bin/sudo", "-n", "/usr/bin/systemd-run", "--quiet", "--collect", "--unit=bivouac-image-poweroff", "--on-active=3s", "--timer-property=AccuracySec=100ms", "/usr/bin/systemctl", "poweroff")
	_, err = g.commands.Output(ctx, g.ssh, args)
	return err
}

func (g *SSHGuest) BootReport(ctx context.Context, r Record) (map[string]uint64, error) {
	b, err := g.command(ctx, r, "boot-report", nil)
	if err != nil {
		return nil, err
	}
	var result map[string]uint64
	if len(b) > 1024 || json.Unmarshal(b, &result) != nil {
		return nil, errors.New("invalid bounded Linux boot report")
	}
	for key := range result {
		switch key {
		case "ssh_active_us", "docker_active_us", "network_wait_active_us", "cloud_init_active_us":
		default:
			return nil, errors.New("unknown Linux boot observation")
		}
	}
	return result, nil
}

func (g *SSHGuest) HelperSHA256() string { return g.helperSHA256 }

// CloneIdentity returns only public hashes for an explicit cold-boot test. The
// machine ID itself and all private SSH key files remain inside the guest.
func (g *SSHGuest) CloneIdentity(ctx context.Context, r Record) (map[string]string, error) {
	args, err := g.arguments(r, false)
	if err != nil {
		return nil, err
	}
	args = append(args, g.opts.User+"@127.0.0.1", "/bin/sh", "-s")
	const script = `set -eu
n=$(/usr/bin/wc -c < /etc/machine-id)
case "$n" in 32|33) ;; *) exit 1;; esac
exec /usr/bin/sha256sum -- /etc/machine-id /etc/ssh/ssh_host_ed25519_key.pub
`
	b, err := g.commands.Input(ctx, g.ssh, args, []byte(script))
	if err != nil {
		return nil, err
	}
	if len(b) > 512 {
		return nil, errors.New("clone identity report exceeds bound")
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		return nil, errors.New("invalid clone identity report")
	}
	result := map[string]string{}
	for i, path := range []string{"/etc/machine-id", "/etc/ssh/ssh_host_ed25519_key.pub"} {
		hash, actual, ok := strings.Cut(lines[i], "  ")
		if !ok || !digest(hash) || actual != path {
			return nil, errors.New("invalid clone identity fingerprint")
		}
		key := "machine_id_sha256"
		if i == 1 {
			key = "ssh_host_key_sha256"
		}
		result[key] = hash
	}
	return result, nil
}
