package vm

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
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
	return nil
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
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() != 0 || port > 1<<32-1 {
		return o, errors.New("invalid vm run arguments")
	}
	o.AgentPort = uint32(port)
	if softnet != "" || block != "" || sudo {
		o.Softnet = &SoftnetOptions{Binary: softnet, Block: block, Sudo: sudo}
	}
	return o, o.validate()
}
