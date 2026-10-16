package vm

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

// RunOptions are the helper's arguments.
type RunOptions struct {
	Dir       string
	Share     string // host directory shared read-only as "bivouac"; empty: none
	Input     bool   // attach keyboard and pointing devices
	AgentPort uint32 // guest agent vsock port
	// AgentSocket is the Unix socket the helper serves AgentPort on.
	AgentSocket string
	Softnet     *SoftnetOptions
	Machine     MachineOptions
}

// MachineOptions are typed overrides of how one VM runs; zero values keep
// the manifest's or the framework's defaults.
type MachineOptions struct {
	// Display overrides the manifest's display (macOS guests).
	Display Display
	// DiskSync is "full" (default: guest flushes reach the disk), "fsync",
	// or "none" (flushes are ignored; disposable guests only).
	DiskSync string
	// Nested enables nested virtualization, which the framework offers to
	// Linux guests on capable hosts (an M3 or newer chip, macOS 15 or later).
	Nested bool
}

// ErrNestedUnsupported reports a host whose framework cannot nest.
var ErrNestedUnsupported = errors.New("this Mac does not support nested virtualization: it needs an M3 or newer chip and macOS 15 or later")

// CheckGuest refuses options the guest m cannot take: nested
// virtualization for a guest other than Linux, or a display for a guest
// other than macOS.
func (o MachineOptions) CheckGuest(m Manifest) error {
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
	if _, err := diskSyncMode(o.DiskSync); err != nil {
		return err
	}
	return o.Display.Validate()
}

// SoftnetOptions isolate the guest behind Softnet instead of shared NAT.
type SoftnetOptions struct {
	Binary string // resolved softnet path
	Sudo   bool   // run through `sudo -n` when the binary is not SUID root
	Block  string // comma-separated CIDRs and @host
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
	if s := o.Softnet; s != nil && (!filepath.IsAbs(s.Binary) || s.Block == "") {
		return errors.New("softnet needs an absolute binary and a block list")
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
	if s := o.Softnet; s != nil {
		args = append(args, "--softnet", s.Binary, "--softnet-block", s.Block)
		if s.Sudo {
			args = append(args, "--softnet-sudo")
		}
	}
	if d := o.Machine.Display; d.Width != 0 {
		args = append(args, "--display", displayArg(d))
	}
	if o.Machine.DiskSync != "" {
		args = append(args, "--disk-sync", o.Machine.DiskSync)
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
	var softnet, block string
	var sudo bool
	fs.StringVar(&o.Dir, "dir", "", "")
	fs.Uint64Var(&port, "agent-port", 0, "")
	fs.StringVar(&o.AgentSocket, "agent-socket", "", "")
	fs.StringVar(&o.Share, "share", "", "")
	fs.BoolVar(&o.Input, "input", false, "")
	fs.StringVar(&softnet, "softnet", "", "")
	fs.StringVar(&block, "softnet-block", "", "")
	fs.BoolVar(&sudo, "softnet-sudo", false, "")
	var display string
	fs.StringVar(&display, "display", "", "")
	fs.StringVar(&o.Machine.DiskSync, "disk-sync", "", "")
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
	if softnet != "" || block != "" || sudo {
		o.Softnet = &SoftnetOptions{Binary: softnet, Block: block, Sudo: sudo}
	}
	return o, o.validate()
}
