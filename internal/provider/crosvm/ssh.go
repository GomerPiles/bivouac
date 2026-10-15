package crosvm

import (
	"context"
	"debug/elf"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/appsandbox"
	"net"
)

type SSHOptions struct{ StateDir, Helper, Key, User string }
type SSHGuest struct {
	opts     SSHOptions
	ssh, scp string
	commands appsandbox.NativeCommands
	cache    *cache.Service
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
	return &SSHGuest{opts: opts, ssh: ssh, scp: scp}, nil
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
	case "prepare", "seed-jit", "launch", "status", "cancel", "diagnostics", "cache-setup", "cache-remove":
	default:
		return nil, errors.New("invalid fixed Linux guest operation")
	}
	args, err := g.arguments(r, false)
	if err != nil {
		return nil, err
	}
	args = append(args, g.opts.User+"@127.0.0.1", "./bivouac-guest", "guest", "linux", mode)
	if input != nil {
		return g.commands.Input(ctx, g.ssh, args, input)
	}
	limit := 1 << 20
	if mode == "diagnostics" {
		limit = 45 << 20
	}
	return g.commands.OutputLimit(ctx, g.ssh, args, limit)
}
func (g *SSHGuest) Ready(ctx context.Context, r Record) error {
	args, err := g.arguments(r, true)
	if err != nil {
		return err
	}
	args = append(args, g.opts.Helper, g.opts.User+"@127.0.0.1:bivouac-guest")
	if _, err := g.commands.Output(ctx, g.scp, args); err != nil {
		return err
	}
	args, err = g.arguments(r, false)
	if err != nil {
		return err
	}
	args = append(args, g.opts.User+"@127.0.0.1", "/usr/bin/chmod", "700", "bivouac-guest")
	if _, err := g.commands.Output(ctx, g.ssh, args); err != nil {
		return err
	}
	cfg := GuestConfig{Name: r.Name, ControllerID: r.Meta.ControllerID, RunnerDir: "/opt/actions-runner", GPU: r.GPU}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	data, err = g.command(ctx, r, "prepare", data)
	if err != nil {
		return err
	}
	var prepared GuestConfig
	if json.Unmarshal(data, &prepared) != nil || prepared.Name != cfg.Name || prepared.ControllerID != cfg.ControllerID || prepared.RunnerDir != cfg.RunnerDir || prepared.GPU != cfg.GPU || len(prepared.BootID) != 36 {
		return errors.New("generic Linux guest readiness was not proven")
	}
	return nil
}
func (g *SSHGuest) StartRunner(ctx context.Context, r Record, jit []byte) error {
	if len(jit) == 0 || len(jit) > 128<<10 {
		return errors.New("invalid bounded JIT input")
	}
	if g.cache != nil {
		cacheErr := g.PrepareCache(ctx, r)
		if cacheErr != nil {
			g.cache.GuestUnavailable(r.Name)
			g.cache.Revoke(r.Name)
			if _, err := g.command(ctx, r, "cache-remove", nil); err != nil {
				return errors.New("remove incomplete Linux guest cache adapter")
			}
		}
	}
	if _, err := g.command(ctx, r, "seed-jit", jit); err != nil {
		return err
	}
	_, err := g.command(ctx, r, "launch", nil)
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
