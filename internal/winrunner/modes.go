package winrunner

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type preflightFacts struct {
	computer, user, consoleUser, desktop string
	console, process                     uint32
	setup, oobe                          uint64
	explorer                             bool
}

type desktopProof struct {
	Ready   bool   `json:"ready"`
	Session uint32 `json:"session"`
	Desktop string `json:"desktop"`
}

func checkPrepareInstance(previous []byte, cfg Config) error {
	var old Config
	if len(previous) > 65536 || json.Unmarshal(previous, &old) != nil || old.RunnerName != cfg.RunnerName || old.ControllerID != cfg.ControllerID {
		return errors.New("guest bootstrap belongs to another instance")
	}
	return nil
}

func preflightReady(cfg Config, f preflightFacts) bool {
	return strings.EqualFold(f.computer, cfg.NativeName) && strings.EqualFold(f.user, cfg.User) &&
		strings.EqualFold(f.consoleUser, cfg.User) && f.console != 0 && f.console != ^uint32(0) &&
		f.process == f.console && f.desktop == "Default" && f.setup == 0 && f.oobe == 0 && f.explorer
}

// waitPreflight requires five consecutive observations separated by 500 ms.
// The caller supplies the overall deadline; a transient failed read resets it.
func waitPreflight(ctx context.Context, cfg Config, facts func() (preflightFacts, error), pause func(context.Context) error) (desktopProof, error) {
	stable := 0
	for {
		if err := ctx.Err(); err != nil {
			return desktopProof{}, errors.New("guest console preflight timed out")
		}
		f, err := facts()
		if err == nil && preflightReady(cfg, f) {
			stable++
		} else {
			stable = 0
		}
		if stable == 5 {
			return desktopProof{true, f.console, f.desktop}, nil
		}
		if pause(ctx) != nil {
			return desktopProof{}, errors.New("guest console preflight timed out")
		}
	}
}

func pauseGuest(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// networkPlan selects the single owned MAC before constructing fixed netsh
// arguments. Static address replaces DHCP addressing, gateways and DNS.
func networkPlan(cfg Config, adapters []net.Interface) ([][]string, error) {
	mac, err := net.ParseMAC(cfg.MAC)
	if err != nil || len(mac) != 6 {
		return nil, errors.New("invalid guest adapter MAC")
	}
	index := 0
	for _, adapter := range adapters {
		if strings.EqualFold(adapter.HardwareAddr.String(), mac.String()) {
			if index != 0 || adapter.Index < 1 {
				return nil, errors.New("owned guest adapter is ambiguous")
			}
			index = adapter.Index
		}
	}
	address, err := netip.ParseAddr(cfg.Address)
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || cfg.Prefix < 1 || cfg.Prefix > 30 || index == 0 {
		return nil, errors.New("invalid static guest address or missing adapter")
	}
	gateway, err := netip.ParseAddr(cfg.Gateway)
	if err != nil || !gateway.Is4() || gateway == address || !netip.PrefixFrom(address, cfg.Prefix).Contains(gateway) {
		return nil, errors.New("invalid guest gateway")
	}
	mask := net.CIDRMask(cfg.Prefix, 32)
	name := "name=" + strconv.Itoa(index)
	return [][]string{
		{"interface", "ipv4", "set", "address", name, "source=static", "address=" + address.String(), "mask=" + net.IP(mask).String(), "gateway=" + gateway.String(), "gwmetric=1", "store=persistent"},
		{"interface", "ipv4", "set", "dnsservers", name, "source=static", "address=1.1.1.1", "register=none", "validate=no"},
		{"interface", "ipv4", "add", "dnsservers", name, "address=8.8.8.8", "index=2", "validate=no"},
	}, nil
}

const (
	maxRunnerFiles = 65536
	maxRunnerFile  = 512 << 20
	maxRunnerBytes = 2 << 30
)

// zipName is intentionally stricter than filepath.IsLocal on Unix: these
// archives will become Windows paths. Reject ADS, DOS devices, aliases, links
// and backslash traversal independent of the platform running the tests.
func zipName(name string) (string, error) {
	name = strings.TrimSuffix(strings.ReplaceAll(name, `\`, "/"), "/")
	if name == "" || len(name) > 1024 || strings.HasPrefix(name, "/") || strings.ContainsAny(name, ":\x00\r\n") {
		return "", errors.New("unsafe runner archive path")
	}
	for _, part := range strings.Split(name, "/") {
		base, _, _ := strings.Cut(strings.ToUpper(part), ".")
		for _, r := range part {
			if r < 32 {
				return "", errors.New("unsafe runner archive component")
			}
		}
		if part == "" || part == "." || part == ".." || strings.TrimRight(part, " .") != part ||
			strings.ContainsAny(part, `<>"|?*`) || base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" || base == "CONOUT$" ||
			(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9') {
			return "", errors.New("unsafe runner archive component")
		}
	}
	return filepath.FromSlash(name), nil
}

func extractRunner(ctx context.Context, archive, destination string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(archive)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 512<<20 {
		return errors.New("invalid bounded runner archive")
	}
	z, err := zip.OpenReader(archive)
	if err != nil {
		return errors.New("open runner archive")
	}
	defer func() { _ = z.Close() }()
	if len(z.File) == 0 || len(z.File) > maxRunnerFiles {
		return errors.New("runner archive entry bound exceeded")
	}
	seen := make(map[string]bool, len(z.File))
	var total uint64
	for _, f := range z.File {
		name, err := zipName(f.Name)
		if err != nil || seen[strings.ToLower(name)] || (!f.Mode().IsRegular() && !f.Mode().IsDir()) || f.UncompressedSize64 > maxRunnerFile {
			return errors.New("unsafe runner archive entry")
		}
		seen[strings.ToLower(name)] = true
		total += f.UncompressedSize64
		if total > maxRunnerBytes {
			return errors.New("runner archive expansion bound exceeded")
		}
	}
	// Never reuse a partial or existing directory. Keep failed output for
	// disposable-guest teardown instead of removing an uncertain path.
	if err := os.Mkdir(destination, 0o700); err != nil {
		return errors.New("archive provisioning requires a fresh runner directory")
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	for _, f := range z.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, err := zipName(f.Name)
		if err != nil {
			return err
		}
		if f.Mode().IsDir() {
			if err := root.MkdirAll(name, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return err
		}
		if err := extractRunnerFile(root, name, f); err != nil {
			return err
		}
	}
	return nil
}

func extractRunnerFile(root *os.Root, name string, entry *zip.File) error {
	in, err := entry.Open()
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(out, io.LimitReader(in, maxRunnerFile+1))
	if err := errors.Join(copyErr, out.Close()); err != nil {
		return errors.New("extract runner archive file")
	}
	if n < 0 || n > maxRunnerFile || uint64(n) != entry.UncompressedSize64 {
		return errors.New("runner archive file expansion differs")
	}
	return nil
}

func parseClock(input io.Reader) (time.Time, error) {
	data, err := io.ReadAll(io.LimitReader(input, 66))
	if err != nil || len(data) == 0 || len(data) > 65 {
		return time.Time{}, errors.New("invalid bounded guest clock input")
	}
	line := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if strings.ContainsAny(line, "\r\n") || !strings.HasSuffix(line, "Z") {
		return time.Time{}, errors.New("guest clock requires one UTC RFC3339 line")
	}
	value, err := time.Parse(time.RFC3339Nano, line)
	if err != nil || value.Year() < 1601 || value.Year() > 9999 {
		return time.Time{}, errors.New("invalid guest UTC clock")
	}
	return value, nil
}

func guestFileExists(root *os.Root, name string) (bool, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("guest state file is not ordinary")
	}
	return true, nil
}

// markAndLaunch is called under the receiver lock. Marker creation is durable
// before dispatch; a failed or uncertain dispatch is deliberately never replayed.
func markAndLaunch(root *os.Root, launch func() error) error {
	for _, name := range []string{"launched", "launch-once", "listener.json", "runner.exit"} {
		exists, err := guestFileExists(root, name)
		if err != nil || exists {
			return errors.New("listener launch is single-use")
		}
	}
	jit, err := root.Lstat("jit")
	if err != nil || !jit.Mode().IsRegular() || jit.Size() == 0 || jit.Size() > 128<<10 {
		return errors.New("private bounded JIT input is missing")
	}
	f, err := root.OpenFile("launched", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("listener launch is single-use")
	}
	syncErr := f.Sync()
	if err := errors.Join(syncErr, f.Close()); err != nil {
		return err
	}
	return launch()
}

func startChecked(root *os.Root, probe, launch func() error) error {
	if probe() != nil {
		return errors.New("detached listener breakaway unavailable")
	}
	return markAndLaunch(root, launch)
}

func stopGuest(root *os.Root, cancel func() error) error {
	exited, err := guestFileExists(root, "runner.exit")
	if err != nil || exited {
		return err
	}
	launched, err := guestFileExists(root, "listener.json")
	if err != nil || !launched {
		return err
	}
	return cancel()
}
