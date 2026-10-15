package tart

import (
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// NetworkPolicy includes every local IPv4 address/subnet (including public
// addresses), and denies private/reserved space and Softnet's default gateway
// exception. No --allow rules or port forwards are ever supplied.
func NetworkPolicy() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	rules := []string{"@host", "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"}
	var reserved []netip.Prefix
	for _, r := range rules[1:] {
		reserved = append(reserved, netip.MustParsePrefix(r))
	}
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				return "", errors.New("unrecognised host interface address")
			}
			if p.Addr().Is4() {
				covered := false
				for _, r := range reserved {
					if r.Contains(p.Masked().Addr()) && r.Bits() <= p.Bits() {
						covered = true
						break
					}
				}
				if !covered {
					rules = append(rules, p.Masked().String(), netip.PrefixFrom(p.Addr(), 32).String())
				}
			}
		}
	}
	sort.Strings(rules)
	return strings.Join(compact(rules), ","), nil
}
func compact(a []string) []string {
	out := a[:0]
	for _, v := range a {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}

// CheckIsolation does not create a network or modify privilege configuration.
// Softnet's hidden probe exits before vmnet/DHCP initialization.
func CheckIsolation(ctx context.Context) (string, error) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return "", errors.New("isolated container pairs require Apple Silicon macOS")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	bin, err := exec.LookPath("softnet")
	if err != nil {
		return "", errors.New("softnet is required; no NAT fallback")
	}
	helper := CLI{Binary: bin}
	h, err := output(ctx, helper, []string{"--help"}, nil, defaultOutputLimit)
	if err != nil || !strings.Contains(string(h), "@host") || !strings.Contains(string(h), "--block") {
		return "", errors.New("softnet must support --block and @host")
	}
	probe := []string{"--vm-fd", "0", "--vm-mac-address", "02:00:00:00:00:01", "--sudo-escalation-probing"}
	fi, err := os.Stat(bin)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSetuid != 0 {
		if !rootSUID(fi) {
			return "", errors.New("softnet SUID binary must be root-owned and not group/world-writable")
		}
		// A SUID binary can probe directly; Tart still refuses if it is not root.
		_, err = output(ctx, helper, probe, nil, defaultOutputLimit)
	} else {
		_, err = output(ctx, CLI{Binary: "sudo"}, append([]string{"-n", bin}, probe...), nil, defaultOutputLimit)
	}
	if err != nil {
		return "", errors.New("softnet privilege probe failed; configure privileges outside bivouac, no VM started")
	}
	return NetworkPolicy()
}

func (p *Provider) preflightEngine(ctx context.Context) error {
	if p.cfg.Containers == nil {
		return nil
	}
	for _, b := range []struct{ name, os string }{{p.cfg.Baseline, "darwin"}, {p.cfg.Containers.Baseline, "linux"}} {
		data, err := os.ReadFile(p.vmDir(b.name) + "/config.json")
		if err != nil {
			return errors.New("container pairs require existing local macOS and Linux baselines")
		}
		var c struct {
			OS   string `json:"os"`
			Arch string `json:"arch"`
		}
		if json.Unmarshal(data, &c) != nil || c.OS != b.os || c.Arch != "arm64" {
			return errors.New("baseline OS/architecture mismatch")
		}
	}
	f, err := elf.Open(p.cfg.Containers.Helper)
	if err != nil {
		return errors.New("containers.helper must be a built Linux/arm64 bivouac binary")
	}
	defer func() { _ = f.Close() }()
	if f.Machine != elf.EM_AARCH64 || f.Class != elf.ELFCLASS64 {
		return errors.New("container helper architecture mismatch")
	}
	_, err = p.isolation(ctx)
	return err
}

// CheckContainers is the read-only doctor/pre-admission check. It never boots
// a baseline, opens a container daemon, or changes privilege configuration.
func (p *Provider) CheckContainers(ctx context.Context) error { return p.preflightEngine(ctx) }
func (p *Provider) isolation(ctx context.Context) (string, error) {
	if p.checkIsolation != nil {
		return p.checkIsolation(ctx)
	}
	return CheckIsolation(ctx)
}

func isolatedArgs(name, policy string) []string {
	return []string{"run", "--no-graphics", "--no-audio", "--no-clipboard", "--no-keyboard", "--no-pointer", "--no-trackpad", "--net-softnet", "--net-softnet-block=" + policy, name}
}
