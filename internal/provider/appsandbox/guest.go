package appsandbox

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/redact"
)

// GuestOptions contains local transport/package locations, never GitHub
// credentials. An unconfigured official runner may be preinstalled or copied
// from a hash-pinned ZIP into each disposable clone.
type GuestOptions struct {
	StateDir      string
	SSHBinary     string
	SCPBinary     string
	SSHKey        string
	Helper        string
	RunnerDir     string
	RunnerArchive string
	RunnerSHA256  string
}
type SSHGuest struct {
	opts     GuestOptions
	commands CommandRunner
	cache    *cache.Service
}

func (g *SSHGuest) SetCache(service *cache.Service) { g.cache = service }

func (g *SSHGuest) PrepareCache(ctx context.Context, l Lease) error {
	if g.cache == nil {
		return nil
	}
	args, err := g.base(l, false)
	if err != nil {
		return err
	}
	input, ok := g.commands.(interface {
		Input(context.Context, string, []string, []byte) ([]byte, error)
	})
	if !ok {
		return errors.New("authenticated cache stdin transport unavailable")
	}
	id, err := instanceKey(l.Record.RunnerName)
	if err != nil {
		return err
	}
	bootstrap, err := g.cache.AttachSSH(ctx, l.Record.RunnerName, cache.SSHBinding{Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(l.SSH.Port)), User: l.SSH.User, KeyFile: g.opts.SSHKey, KnownHosts: filepath.Join(g.opts.StateDir, id+".known_hosts")})
	if err != nil {
		return err
	}
	defer clear(bootstrap)
	args = append(args, l.SSH.User+"@127.0.0.1", `C:\ProgramData\Bivouac\Guest\bivouac.exe`, "guest", "windows", "cache-setup")
	_, err = input.Input(ctx, g.opts.SSHBinary, args, bootstrap)
	return err
}

type guestConfig struct {
	NativeName    string `json:"native_name"`
	RunnerName    string `json:"runner_name"`
	ControllerID  string `json:"controller_id"`
	User          string `json:"user"`
	RunnerDir     string `json:"runner_dir"`
	Address       string `json:"address"`
	Gateway       string `json:"gateway"`
	Prefix        int    `json:"prefix"`
	MAC           string `json:"mac"`
	Archive       bool   `json:"archive"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

func NewSSHGuest(opts GuestOptions, commands CommandRunner) (*SSHGuest, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New("windows guest transport requires a Windows host")
	}
	for _, path := range []string{opts.StateDir, opts.SSHBinary, opts.SCPBinary, opts.SSHKey, opts.Helper} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			return nil, errors.New("guest transport requires absolute local paths")
		}
	}
	if !validRunnerPath(opts.RunnerDir) {
		return nil, errors.New("guest runner must use a dedicated absolute Windows directory")
	}
	if opts.RunnerArchive != "" {
		if !filepath.IsAbs(opts.RunnerArchive) || len(opts.RunnerSHA256) != 64 {
			return nil, errors.New("runner archive requires an absolute path and SHA-256")
		}
		if err := verifyArchive(opts.RunnerArchive, opts.RunnerSHA256); err != nil {
			return nil, err
		}
	} else if opts.RunnerSHA256 != "" {
		return nil, errors.New("runner hash without an archive")
	}
	if commands == nil {
		commands = NativeCommands{}
	}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, err
	}
	return &SSHGuest{opts: opts, commands: commands}, nil
}
func validRunnerPath(path string) bool {
	// Restrict to a fixed local guest drive. Config is delivered as JSON, not
	// interpolated into a remote command or scheduled-task command line.
	return len(path) > 3 && strings.EqualFold(path[:3], `C:\`) &&
		!strings.ContainsAny(path, "\x00\r\n") && !strings.Contains(path, "..") &&
		!strings.EqualFold(strings.TrimRight(path, `\`), `C:\Windows`) &&
		!strings.HasPrefix(strings.ToLower(path), `c:\windows\`)
}
func verifyArchive(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.New("runner archive unavailable")
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 512<<20 {
		return errors.New("invalid bounded runner archive")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return errors.New("read runner archive")
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected) {
		return errors.New("runner archive hash differs")
	}
	return nil
}
func (g *SSHGuest) base(l Lease, scp bool) ([]string, error) {
	if !l.SSH.ForwardReady() || !identifier(l.SSH.User, 32) || l.Record.NativeName == "" {
		return nil, errors.New("owned loopback SSH binding unavailable")
	}
	id, err := instanceKey(l.Record.RunnerName)
	if err != nil || id != l.Record.Meta.InstanceID {
		return nil, provider.ErrNotOwned
	}
	known := filepath.Join(g.opts.StateDir, id+".known_hosts")
	strict := "yes"
	if _, err := os.Stat(known); errors.Is(err, os.ErrNotExist) {
		strict = "accept-new"
	} else if err != nil {
		return nil, err
	}
	flag := "-p"
	if scp {
		flag = "-P"
	}
	return []string{"-F", "NUL", flag, strconv.Itoa(l.SSH.Port), "-i", g.opts.SSHKey,
		"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
		"-o", "GlobalKnownHostsFile=NUL", "-o", "UserKnownHostsFile=" + known,
		"-o", "StrictHostKeyChecking=" + strict, "-o", "ConnectTimeout=10"}, nil
}

// Forget removes the instance's pinned host key after confirmed deletion, so
// host state does not grow and a reused instance ID never inherits a key.
func (g *SSHGuest) Forget(name string) error {
	id, err := instanceKey(name)
	if err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(g.opts.StateDir, id+".known_hosts")); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
func (g *SSHGuest) control(ctx context.Context, l Lease, mode string) ([]byte, error) {
	switch mode {
	case "prepare", "start", "status", "stop", "diag":
	default:
		return nil, errors.New("invalid fixed guest operation")
	}
	args, err := g.base(l, false)
	if err != nil {
		return nil, err
	}
	args = append(args, l.SSH.User+"@127.0.0.1", "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "bivouac-control.ps1", "-Mode", mode)
	return g.commands.Output(ctx, g.opts.SSHBinary, args)
}
func (g *SSHGuest) copy(ctx context.Context, l Lease, local, remote string) error {
	if remote != "bivouac-preflight.ps1" && remote != "bivouac-control.ps1" && remote != "bivouac-helper.exe" && remote != "bivouac-config.json" && remote != "bivouac-runner.zip" {
		return errors.New("invalid fixed guest transfer")
	}
	args, err := g.base(l, true)
	if err != nil {
		return err
	}
	target := l.SSH.User + "@127.0.0.1:" + remote
	args = append(args, local, target)
	_, err = g.commands.Output(ctx, g.opts.SCPBinary, args)
	return err
}
func (g *SSHGuest) stage() (string, func(), error) {
	dir, err := PrivateGuestDirectory(g.opts.StateDir)
	if err != nil {
		return "", nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		_ = os.Remove(dir)
		return "", nil, err
	}
	return dir, func() {
		for _, name := range []string{"bivouac-preflight.ps1", "bivouac-control.ps1", "bivouac-config.json", "bivouac-diagnostics.zip"} {
			_ = root.Remove(name)
		}
		_ = root.Close()
		_ = os.Remove(dir)
	}, nil
}

// Preflight waits over the NIC-independent HvSocket transport. It delivers no
// runner or credential and performs no guest or host network mutation.
func (g *SSHGuest) Preflight(ctx context.Context, l Lease) error {
	dir, cleanup, err := g.stage()
	if err != nil {
		return err
	}
	defer cleanup()
	data, err := json.Marshal(guestConfig{NativeName: l.Record.NativeName, RunnerName: l.Record.RunnerName, ControllerID: l.Record.Meta.ControllerID, User: l.SSH.User})
	if err != nil {
		return err
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{"bivouac-preflight.ps1", []byte(windowsPreflight)}, {"bivouac-config.json", data}} {
		path := filepath.Join(dir, file.name)
		if err = os.WriteFile(path, file.data, 0o600); err != nil {
			return err
		}
		if err = g.copy(ctx, l, path, file.name); err != nil {
			return err
		}
	}
	args, err := g.base(l, false)
	if err != nil {
		return err
	}
	args = append(args, l.SSH.User+"@127.0.0.1", "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "bivouac-preflight.ps1")
	data, err = g.commands.Output(ctx, g.opts.SSHBinary, args)
	if err != nil {
		return err
	}
	var result struct {
		Ready   bool   `json:"ready"`
		Session uint32 `json:"session"`
	}
	if json.Unmarshal(data, &result) != nil || !result.Ready || result.Session == 0 || result.Session == ^uint32(0) {
		return errors.New("guest console preflight was not proven")
	}
	return nil
}
func (g *SSHGuest) Ready(ctx context.Context, l Lease) error {
	address, aerr := netip.ParseAddr(l.Address)
	gateway, gerr := netip.ParseAddr(l.Gateway)
	if aerr != nil || gerr != nil || !address.Is4() || !address.IsPrivate() || !gateway.Is4() || l.Prefix != 28 || len(l.MAC) != 17 {
		return errors.New("invalid isolated guest network lease")
	}
	dir, cleanup, err := g.stage()
	if err != nil {
		return err
	}
	defer cleanup()
	config := guestConfig{NativeName: l.Record.NativeName, RunnerName: l.Record.RunnerName, ControllerID: l.Record.Meta.ControllerID, User: l.SSH.User, RunnerDir: g.opts.RunnerDir, Address: l.Address, Gateway: l.Gateway, Prefix: l.Prefix, MAC: l.MAC, Archive: g.opts.RunnerArchive != "", ArchiveSHA256: g.opts.RunnerSHA256}
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	for _, file := range []struct {
		name string
		data []byte
	}{
		{"bivouac-control.ps1", []byte(windowsControl)},
		{"bivouac-config.json", data},
	} {
		path := filepath.Join(dir, file.name)
		if err := os.WriteFile(path, file.data, 0o600); err != nil {
			return err
		}
		if err := g.copy(ctx, l, path, file.name); err != nil {
			return err
		}
	}
	if err := g.copy(ctx, l, g.opts.Helper, "bivouac-helper.exe"); err != nil {
		return err
	}
	if g.opts.RunnerArchive != "" {
		if err := verifyArchive(g.opts.RunnerArchive, g.opts.RunnerSHA256); err != nil {
			return err
		}
		if err := g.copy(ctx, l, g.opts.RunnerArchive, "bivouac-runner.zip"); err != nil {
			return err
		}
	}
	data, err = g.control(ctx, l, "prepare")
	if err != nil {
		return err
	}
	var probe struct {
		Ready   bool   `json:"ready"`
		Session uint32 `json:"session"`
		Desktop string `json:"desktop"`
	}
	if json.Unmarshal(data, &probe) != nil || !probe.Ready || probe.Session == 0 || probe.Desktop != "Default" {
		return errors.New("guest interactive desktop readiness was not proven")
	}
	return nil
}
func (g *SSHGuest) StartRunner(ctx context.Context, l Lease, jit []byte) error {
	if len(jit) == 0 || len(jit) > 128<<10 {
		return errors.New("invalid bounded JIT input")
	}
	input, ok := g.commands.(interface {
		Input(context.Context, string, []string, []byte) ([]byte, error)
	})
	if !ok {
		return errors.New("authenticated SSH stdin transport unavailable")
	}
	args, err := g.base(l, false)
	if err != nil {
		return err
	}
	if g.cache != nil {
		cacheErr := g.PrepareCache(ctx, l)
		if cacheErr != nil {
			g.cache.GuestUnavailable(l.Record.RunnerName)
			g.cache.Revoke(l.Record.RunnerName)
			cacheArgs := append(slices.Clone(args), l.SSH.User+"@127.0.0.1", `C:\ProgramData\Bivouac\Guest\bivouac.exe`, "guest", "windows", "cache-remove")
			if _, err = input.Input(ctx, g.opts.SSHBinary, cacheArgs, nil); err != nil {
				return errors.New("remove incomplete guest cache adapter")
			}
		}
	}
	args = append(args, l.SSH.User+"@127.0.0.1", `C:\ProgramData\Bivouac\Guest\bivouac.exe`, "guest", "windows", "seed-jit")
	if _, err := input.Input(ctx, g.opts.SSHBinary, args, jit); err != nil {
		return err
	}
	_, err = g.control(ctx, l, "start")
	return err
}
func (g *SSHGuest) StopRunner(ctx context.Context, l Lease) error {
	_, err := g.control(ctx, l, "stop")
	return err
}
func (g *SSHGuest) RunnerStatus(ctx context.Context, l Lease) (provider.RunnerStatus, error) {
	data, err := g.control(ctx, l, "status")
	if err != nil {
		return provider.RunnerStatus{}, err
	}
	var result provider.RunnerStatus
	if json.Unmarshal(data, &result) != nil {
		return result, errors.New("invalid bounded guest runner status")
	}
	switch result.State {
	case provider.RunnerAbsent, provider.RunnerStarting, provider.RunnerListening, provider.RunnerRunning, provider.RunnerExited:
		return result, nil
	default:
		return provider.RunnerStatus{}, errors.New("unknown guest runner status")
	}
}
func (g *SSHGuest) CollectDiagnostics(ctx context.Context, l Lease, destination string) error {
	args, err := g.base(l, false)
	if err != nil {
		return err
	}
	args = append(args, l.SSH.User+"@127.0.0.1", "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "bivouac-control.ps1", "-Mode", "diag")
	var data []byte
	if limited, ok := g.commands.(interface {
		OutputLimit(context.Context, string, []string, int) ([]byte, error)
	}); ok {
		data, err = limited.OutputLimit(ctx, g.opts.SSHBinary, args, 45<<20)
	} else {
		data, err = g.commands.Output(ctx, g.opts.SSHBinary, args)
	}
	if err != nil {
		return err
	}
	decoded, err := io.ReadAll(io.LimitReader(base64.NewDecoder(base64.StdEncoding, strings.NewReader(string(data))), 32<<20+1))
	if err != nil || len(decoded) > 32<<20 {
		return errors.New("invalid bounded guest diagnostics stream")
	}
	dir, cleanup, err := g.stage()
	if err != nil {
		return err
	}
	defer cleanup()
	path := filepath.Join(dir, "bivouac-diagnostics.zip")
	if err := os.WriteFile(path, decoded, 0o600); err != nil {
		return err
	}
	return extractDiagnostics(path, destination)
}
func extractDiagnostics(path, destination string) error {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return errors.New("invalid guest diagnostic archive")
	}
	defer func() { _ = reader.Close() }()
	if len(reader.File) > 1024 {
		return errors.New("too many guest diagnostic files")
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	var total uint64
	for _, file := range reader.File {
		name := file.Name
		if file.Mode().IsDir() {
			continue
		}
		if !file.Mode().IsRegular() || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") || strings.Contains(name, "..") || (name != "runner.log" && name != perf.FileName && !strings.HasPrefix(name, "_diag/")) {
			return errors.New("unsafe guest diagnostic path")
		}
		total += file.UncompressedSize64
		if file.UncompressedSize64 > 16<<20 || total > 128<<20 {
			return errors.New("guest diagnostics exceed bound")
		}
		if err := root.MkdirAll(filepath.Dir(filepath.FromSlash(name)), 0o700); err != nil {
			return err
		}
		input, err := file.Open()
		if err != nil {
			return err
		}
		if name == perf.FileName {
			report, readErr := perf.DecodeReport(input)
			_ = input.Close()
			if readErr != nil {
				// Optional telemetry must not prevent collecting official logs.
				continue
			}
			output, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			sink := redact.NewWriter(output)
			err = errors.Join(json.NewEncoder(sink).Encode(report), sink.Close(), output.Close())
			if err != nil {
				return err
			}
			continue
		}
		output, err := root.OpenFile(filepath.FromSlash(name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = input.Close()
			return err
		}
		sink := redact.NewWriter(output)
		_, copyErr := io.Copy(sink, io.LimitReader(input, 16<<20+1))
		err = errors.Join(copyErr, sink.Close(), output.Close(), input.Close())
		if err != nil {
			return err
		}
	}
	return nil
}

// ExtractDiagnostics shares the bounded, path-checked, redacted host sink
// across Windows and Linux guest transports. The archive is always untrusted.
func ExtractDiagnostics(path, destination string) error { return extractDiagnostics(path, destination) }
