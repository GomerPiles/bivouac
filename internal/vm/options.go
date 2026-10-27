package vm

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/GomerPiles/bivouac/internal/config"
)

// RunOptions are the helper's arguments.
type RunOptions struct {
	Dir       string
	Share     string // host directory shared read-only as "bivouac"; empty: none
	Input     bool   // attach keyboard and pointing devices
	AgentPort uint32 // guest agent vsock port
	// AgentSocket is the Unix socket the helper serves AgentPort on.
	AgentSocket         string
	RootlessNetwork     bool
	Network             config.VZNetwork
	CacheMaxConnections int
	Machine             MachineOptions
}

// MachineOptions are typed overrides of how one VM runs; zero values keep
// the manifest's or the framework's defaults.
type MachineOptions struct {
	// Factory disks are Linux-only, fixed-role attachments; never runner devices.
	SeedDisk    string
	ReceiptDisk string
	// Display overrides the manifest's display (macOS guests).
	Display Display
	// DiskSync is "full" (default: guest flushes reach the disk), "fsync",
	// or "none" (flushes are ignored; disposable guests only).
	DiskSync string
	// Nested enables nested virtualization, which the framework offers to
	// Linux guests on capable hosts (an M3 or newer chip, macOS 15 or later).
	Nested bool
}

// ErrForcedStop distinguishes host power-off from a guest-initiated shutdown.
var ErrForcedStop = errors.New("host forced power-off")

// ErrNestedUnsupported reports a host whose framework cannot nest.
var ErrNestedUnsupported = errors.New("this Mac does not support nested virtualization: it needs an M3 or newer chip and macOS 15 or later")

// CheckGuest refuses options the guest m cannot take: nested
// virtualization for a guest other than Linux, or a display for a guest
// other than macOS.
func (o MachineOptions) CheckGuest(m Manifest) error {
	if (o.SeedDisk != "" || o.ReceiptDisk != "") && m.OS != "linux" {
		return errors.New("factory disks require a Linux guest")
	}
	if o.Nested && m.OS != "linux" {
		return fmt.Errorf("nested virtualization is available only to Linux guests, not %s: Apple's Virtualization framework offers it to no macOS guest", m.OS)
	}
	if o.Display.Width != 0 && m.OS != "darwin" {
		return fmt.Errorf("a display applies only to macOS guests, not %s", m.OS)
	}
	return nil
}

// VZDiskImageSynchronizationMode values.
const (
	syncFull  = 1
	syncFsync = 2
	syncNone  = 3
)

func diskSyncMode(name string) (int, error) {
	switch name {
	case "", "full":
		return syncFull, nil
	case "fsync":
		return syncFsync, nil
	case "none":
		return syncNone, nil
	}
	return 0, fmt.Errorf("disk sync mode %q is not full, fsync, or none", name)
}

// Validate checks the options without a VM.
func (o MachineOptions) Validate() error {
	for _, p := range []string{o.SeedDisk, o.ReceiptDisk} {
		if p != "" && (!filepath.IsAbs(p) || strings.ContainsAny(p, "\x00\r\n")) {
			return errors.New("factory disk path must be absolute")
		}
	}
	if o.SeedDisk != "" || o.ReceiptDisk != "" {
		if o.DiskSync != "" && o.DiskSync != "full" {
			return errors.New("factory disks require full synchronization")
		}
	}
	if _, err := diskSyncMode(o.DiskSync); err != nil {
		return err
	}
	return o.Display.Validate()
}

func (o RunOptions) validate() error {
	if !filepath.IsAbs(o.Dir) {
		return errors.New("VM directory must be absolute")
	}
	if o.Share != "" && !filepath.IsAbs(o.Share) {
		return errors.New("shared directory must be absolute")
	}
	if o.AgentPort == 0 {
		return errors.New("guest agent port is required")
	}
	if !filepath.IsAbs(o.AgentSocket) || len(o.AgentSocket) > maxSocketPath {
		return fmt.Errorf("guest agent socket must be an absolute path of at most %d bytes", maxSocketPath)
	}
	if err := o.Network.Validate(); err != nil {
		return err
	}
	if o.CacheMaxConnections < 0 || o.CacheMaxConnections > 65536 {
		return errors.New("invalid cache connection bound")
	}
	return o.Machine.Validate()
}

// displayArg encodes a display as WIDTHxHEIGHT[@PPI].
func displayArg(d Display) string {
	s := strconv.Itoa(d.Width) + "x" + strconv.Itoa(d.Height)
	if d.PPI != 0 {
		s += "@" + strconv.Itoa(d.PPI)
	}
	return s
}

func parseDisplayArg(s string) (Display, error) {
	var d Display
	size, ppi, hasPPI := strings.Cut(s, "@")
	w, h, ok := strings.Cut(size, "x")
	var err error
	if d.Width, err = strconv.Atoi(w); err != nil || !ok {
		return d, fmt.Errorf("invalid display %q", s)
	}
	if d.Height, err = strconv.Atoi(h); err != nil {
		return d, fmt.Errorf("invalid display %q", s)
	}
	if hasPPI {
		if d.PPI, err = strconv.Atoi(ppi); err != nil || d.PPI == 0 {
			return d, fmt.Errorf("invalid display %q", s)
		}
	}
	if d.Width == 0 {
		return d, fmt.Errorf("invalid display %q", s)
	}
	return d, d.Validate()
}

// Args is the helper's argument array after `vm run`. It is recorded in
// the launch log and diagnostics, so it never carries a secret.
func (o RunOptions) Args() []string {
	args := []string{"--dir", o.Dir, "--agent-port", strconv.FormatUint(uint64(o.AgentPort), 10), "--agent-socket", o.AgentSocket}
	if o.Share != "" {
		args = append(args, "--share", o.Share)
	}
	if o.Input {
		args = append(args, "--input")
	}
	if o.RootlessNetwork {
		args = append(args, "--rootless-network")
		args = append(args, NetworkArgs(o.Network)...)
		if o.CacheMaxConnections != 0 {
			args = append(args, "--cache-max-connections", strconv.Itoa(o.CacheMaxConnections))
		}
	}
	if d := o.Machine.Display; d.Width != 0 {
		args = append(args, "--display", displayArg(d))
	}
	if o.Machine.DiskSync != "" {
		args = append(args, "--disk-sync", o.Machine.DiskSync)
	}
	if o.Machine.SeedDisk != "" {
		args = append(args, "--seed-disk", o.Machine.SeedDisk)
	}
	if o.Machine.ReceiptDisk != "" {
		args = append(args, "--receipt-disk", o.Machine.ReceiptDisk)
	}
	if o.Machine.Nested {
		args = append(args, "--nested")
	}
	return args
}

// ParseArgs reverses Args.
func ParseArgs(args []string) (RunOptions, error) {
	fs := flag.NewFlagSet("vm run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o RunOptions
	var port uint64
	fs.StringVar(&o.Dir, "dir", "", "")
	fs.Uint64Var(&port, "agent-port", 0, "")
	fs.StringVar(&o.AgentSocket, "agent-socket", "", "")
	fs.StringVar(&o.Share, "share", "", "")
	fs.BoolVar(&o.Input, "input", false, "")
	fs.BoolVar(&o.RootlessNetwork, "rootless-network", false, "")
	networkFlags(fs, &o.Network)
	fs.IntVar(&o.CacheMaxConnections, "cache-max-connections", 0, "")
	var display string
	fs.StringVar(&display, "display", "", "")
	fs.StringVar(&o.Machine.DiskSync, "disk-sync", "", "")
	fs.StringVar(&o.Machine.SeedDisk, "seed-disk", "", "")
	fs.StringVar(&o.Machine.ReceiptDisk, "receipt-disk", "", "")
	fs.BoolVar(&o.Machine.Nested, "nested", false, "")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() != 0 || port > 1<<32-1 {
		return o, errors.New("invalid vm run arguments")
	}
	o.AgentPort = uint32(port)
	if display != "" {
		d, err := parseDisplayArg(display)
		if err != nil {
			return o, err
		}
		o.Machine.Display = d
	}
	return o, o.validate()
}

// NetworkArgs carries only typed settings, never raw provider launch options.
func NetworkArgs(n config.VZNetwork) []string {
	n = n.WithDefaults()
	args := []string{"--network-memory-mb", strconv.Itoa(n.MemoryMB), "--network-max-flows", strconv.Itoa(n.MaxFlows), "--network-tcp-idle", n.TCPIdleTimeout.String(), "--network-udp-idle", n.UDPIdleTimeout.String(), "--network-mtu", strconv.Itoa(n.MTU)}
	for _, server := range n.DNSServers {
		args = append(args, "--network-dns-server", server)
	}
	return args
}
func networkFlags(fs *flag.FlagSet, n *config.VZNetwork) {
	fs.IntVar(&n.MemoryMB, "network-memory-mb", 0, "")
	fs.IntVar(&n.MaxFlows, "network-max-flows", 0, "")
	fs.DurationVar(&n.TCPIdleTimeout.Duration, "network-tcp-idle", 0, "")
	fs.DurationVar(&n.UDPIdleTimeout.Duration, "network-udp-idle", 0, "")
	fs.IntVar(&n.MTU, "network-mtu", 0, "")
	fs.Func("network-dns-server", "", func(s string) error { n.DNSServers = append(n.DNSServers, s); return nil })
}
func ParseNetworkArgs(args []string) (config.VZNetwork, error) {
	var n config.VZNetwork
	fs := flag.NewFlagSet("vm network", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	networkFlags(fs, &n)
	if err := fs.Parse(args); err != nil {
		return n, err
	}
	if fs.NArg() != 0 {
		return n, errors.New("invalid network arguments")
	}
	return n, n.Validate()
}
