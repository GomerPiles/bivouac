package linuxguest

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
)

type guestCommands interface {
	Output(context.Context, string, []string) ([]byte, error)
	OutputLimit(context.Context, string, []string, int) ([]byte, error)
	Input(context.Context, string, []string, []byte) ([]byte, error)
}

// The fixed kernel launch disables predictable naming: the isolated virtio
// uplink is eth0. Do not configure Docker bridges or loopback profiles.
func uplinkProfile(data []byte) (string, error) {
	if len(data) > 65536 {
		return "", errors.New("guest network profile inventory exceeds bound")
	}
	profile := ""
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		id, device, ok := strings.Cut(line, ":")
		if !ok {
			return "", errors.New("invalid guest network profile inventory")
		}
		if device != "eth0" {
			continue
		}
		if profile != "" || len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			return "", errors.New("ambiguous or invalid guest uplink profile")
		}
		decoded, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
		if err != nil || len(decoded) != 16 {
			return "", errors.New("invalid guest uplink UUID")
		}
		profile = id
	}
	if profile == "" {
		return "", errors.New("active generic eth0 profile is missing")
	}
	return profile, nil
}

const publicResolverFile = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"

type dnsPreparation struct{ Reused, ProfileChanged, ResolverChanged, DHCP bool }

func publicResolverSet(values []string) bool {
	if len(values) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value != "1.1.1.1" && value != "8.8.8.8" || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
func publicProfile(data []byte) bool {
	if len(data) > 4096 {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 4 || lines[0] != "yes" || lines[2] != "yes" || lines[3] != "" {
		return false
	}
	return publicResolverSet(strings.FieldsFunc(lines[1], func(r rune) bool { return r == ',' || r == ' ' }))
}
func publicActiveDNS(data []byte) bool {
	if len(data) > 4096 {
		return false
	}
	return publicResolverSet(strings.FieldsFunc(string(data), func(r rune) bool { return r == ',' || r == '|' || r == ' ' || r == '\n' || r == '\t' }))
}

// Loopback resolved stubs are acceptable only after the active NetworkManager
// upstreams have independently been verified as exactly the two public servers.
func publicResolver(data []byte, allowStub bool) bool {
	if len(data) > 65536 {
		return false
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "nameserver" {
			continue
		}
		if len(fields) != 2 {
			return false
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			return false
		}
		servers = append(servers, addr.String())
	}
	if publicResolverSet(servers) {
		return true
	}
	return allowStub && len(servers) == 1 && (servers[0] == "127.0.0.53" || servers[0] == "127.0.0.54")
}
func configurePublicDNS(ctx context.Context, nm bool, readResolver func() ([]byte, error), commands guestCommands) (r dnsPreparation, result error) {
	stage := uint32(1)
	defer func() {
		if result != nil {
			result = &dnsError{stage: stage}
		}
	}()
	if nm {
		data, err := commands.OutputLimit(ctx, "/usr/bin/nmcli", []string{"-t", "-f", "UUID,DEVICE", "connection", "show", "--active"}, 65536)
		if err != nil {
			return r, errors.New("inspect generic guest network profile")
		}
		stage = 2
		profile, err := uplinkProfile(data)
		if err != nil {
			return r, err
		}
		profileArgs := []string{"-g", "ipv4.ignore-auto-dns,ipv4.dns,ipv6.ignore-auto-dns,ipv6.dns", "connection", "show", "uuid", profile}
		activeArgs := []string{"-g", "IP4.DNS,IP6.DNS", "device", "show", "eth0"}
		stage = 3
		data, err = commands.OutputLimit(ctx, "/usr/bin/nmcli", profileArgs, 4096)
		if err != nil {
			return r, errors.New("inspect persistent public guest DNS")
		}
		correct := publicProfile(data)
		if !correct {
			args := []string{"-n", "/usr/bin/nmcli", "connection", "modify", "uuid", profile, "ipv4.ignore-auto-dns", "yes", "ipv4.dns", "1.1.1.1,8.8.8.8", "ipv6.ignore-auto-dns", "yes", "ipv6.dns", ""}
			stage = 4
			if _, err = commands.Output(ctx, "/usr/bin/sudo", args); err != nil {
				return r, errors.New("persist public guest DNS")
			}
			r.ProfileChanged = true
		}
		stage = 5
		active, err := commands.OutputLimit(ctx, "/usr/bin/nmcli", activeArgs, 4096)
		if err != nil {
			return r, errors.New("inspect active public guest DNS")
		}
		if !correct || !publicActiveDNS(active) {
			stage = 6
			if _, err = commands.Output(ctx, "/usr/bin/sudo", []string{"-n", "/usr/bin/nmcli", "device", "reapply", "eth0"}); err != nil {
				return r, errors.New("apply public guest DNS without changing addresses")
			}
			// A profile repair is not sufficient proof that its live DNS changed.
			stage = 7
			data, err = commands.OutputLimit(ctx, "/usr/bin/nmcli", profileArgs, 4096)
			if err != nil || !publicProfile(data) {
				return r, errors.New("persistent guest DNS policy unconfirmed")
			}
			stage = 8
			active, err = commands.OutputLimit(ctx, "/usr/bin/nmcli", activeArgs, 4096)
			if err != nil || !publicActiveDNS(active) {
				return r, errors.New("active guest DNS policy unconfirmed")
			}
			r.ProfileChanged = true
		}
	}
	stage = 9
	data, err := readResolver()
	if err != nil {
		return r, errors.New("inspect guest resolver file")
	}
	if !publicResolver(data, nm) {
		stage = 10
		if _, err = commands.Input(ctx, "/usr/bin/sudo", []string{"-n", "/usr/bin/tee", "/etc/resolv.conf"}, []byte(publicResolverFile)); err != nil {
			return r, errors.New("configure public guest resolver")
		}
		stage = 11
		data, err = readResolver()
		if err != nil || !publicResolver(data, false) {
			return r, errors.New("guest resolver policy unconfirmed")
		}
		r.ResolverChanged = true
	}
	r.Reused = !r.ProfileChanged && !r.ResolverChanged
	return r, nil
}

type dnsError struct{ stage uint32 }

func (e *dnsError) Error() string { return "public guest DNS preparation failed" }
