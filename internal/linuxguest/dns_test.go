package linuxguest

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDNSSelectsOnlyOneValidUplinkProfile(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc"
	got, err := uplinkProfile([]byte(id + ":eth0\n22345678-1234-1234-1234-123456789abc:docker0\n"))
	if err != nil || got != id {
		t.Fatal("uplink selection failed")
	}
	for _, value := range []string{"", id + ":docker0", id + ":eth0\n" + id + ":eth0", "not-a-uuid:eth0", "malformed", "123456781234-1234-1234-1234-12345678:eth0"} {
		if _, err := uplinkProfile([]byte(value)); err == nil {
			t.Fatal("unsafe/ambiguous uplink accepted")
		}
	}
}

type dnsFixture struct {
	profile, active         string
	resolver                []byte
	modify, reapply, writes int
	repair                  bool
	fail                    bool
}

const dnsUUID = "12345678-1234-1234-1234-123456789abc"

func (f *dnsFixture) Output(ctx context.Context, binary string, args []string) ([]byte, error) {
	return f.OutputLimit(ctx, binary, args, 65536)
}
func (f *dnsFixture) OutputLimit(_ context.Context, binary string, args []string, _ int) ([]byte, error) {
	if f.fail {
		return nil, errors.New("synthetic command failure")
	}
	joined := strings.Join(args, " ")
	switch {
	case binary == "/usr/bin/nmcli" && strings.Contains(joined, "UUID,DEVICE"):
		return []byte(dnsUUID + ":eth0\n"), nil
	case binary == "/usr/bin/nmcli" && strings.Contains(joined, "ipv4.ignore-auto-dns"):
		return []byte(f.profile), nil
	case binary == "/usr/bin/nmcli" && strings.Contains(joined, "IP4.DNS"):
		return []byte(f.active), nil
	case binary == "/usr/bin/sudo" && strings.Contains(joined, "connection modify"):
		f.modify++
		if f.repair {
			f.profile = "yes\n1.1.1.1,8.8.8.8\nyes\n\n"
		}
		return nil, nil
	case binary == "/usr/bin/sudo" && strings.Contains(joined, "device reapply eth0"):
		f.reapply++
		if f.repair {
			f.active = "1.1.1.1\n8.8.8.8\n"
		}
		return nil, nil
	default:
		return nil, errors.New("unexpected DNS command")
	}
}
func (f *dnsFixture) Input(_ context.Context, binary string, args []string, b []byte) ([]byte, error) {
	if binary != "/usr/bin/sudo" || strings.Join(args, " ") != "-n /usr/bin/tee /etc/resolv.conf" || string(b) != publicResolverFile {
		return nil, errors.New("unexpected resolver write")
	}
	f.writes++
	if f.repair {
		f.resolver = append([]byte(nil), b...)
	}
	return nil, nil
}
func TestDNSPreparedProfilesAvoidAllMutations(t *testing.T) {
	for _, resolver := range []string{publicResolverFile, "nameserver 127.0.0.53\n"} {
		f := &dnsFixture{profile: "yes\n1.1.1.1,8.8.8.8\nyes\n\n", active: "1.1.1.1\n8.8.8.8\n", resolver: []byte(resolver)}
		r, err := configurePublicDNS(context.Background(), true, func() ([]byte, error) { return f.resolver, nil }, f)
		if err != nil || !r.Reused || f.modify+f.reapply+f.writes != 0 {
			t.Fatal("prepared DNS was rewritten", r, err)
		}
	}
}
func TestDNSRepairsOnlyChangedStateAndVerifiesResult(t *testing.T) {
	for _, kind := range []string{"profile", "active", "resolver", "repair-failed", "command-failed"} {
		t.Run(kind, func(t *testing.T) {
			f := &dnsFixture{profile: "yes\n1.1.1.1,8.8.8.8\nyes\n\n", active: "1.1.1.1\n8.8.8.8\n", resolver: []byte(publicResolverFile), repair: true}
			switch kind {
			case "profile":
				f.profile = "no\n10.0.2.3\nno\n\n"
			case "active":
				f.active = "10.0.2.3\n"
			case "resolver":
				f.resolver = []byte("nameserver 10.0.2.3\n")
			case "repair-failed":
				f.active = "10.0.2.3\n"
				f.repair = false
			case "command-failed":
				f.fail = true
			}
			r, err := configurePublicDNS(context.Background(), true, func() ([]byte, error) { return f.resolver, nil }, f)
			if kind == "repair-failed" || kind == "command-failed" {
				if err == nil {
					t.Fatal("unverified DNS admitted")
				}
				return
			}
			if err != nil || r.Reused {
				t.Fatal("DNS repair failed", r, err)
			}
			if kind == "profile" && (f.modify != 1 || f.reapply != 1 || f.writes != 0) || kind == "active" && (f.modify != 0 || f.reapply != 1 || f.writes != 0) || kind == "resolver" && (f.modify+f.reapply != 0 || f.writes != 1) {
				t.Fatal("unnecessary DNS mutations", f)
			}
		})
	}
}
func TestDNSRejectsUnsafeResolverAndUpstreamFacts(t *testing.T) {
	for _, value := range []string{"", "nameserver 127.0.0.53\n", "nameserver 10.0.2.3\n", "nameserver ::1\n", "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 10.0.2.3\n", "nameserver 1.1.1.1 extra\n"} {
		if publicResolver([]byte(value), false) {
			t.Fatal("unsafe static resolver accepted")
		}
	}
	for _, value := range []string{"1.1.1.1\n", "1.1.1.1\n8.8.8.8\n10.0.2.3\n", "1.1.1.1\n8.8.8.8\n::1\n"} {
		if publicActiveDNS([]byte(value)) {
			t.Fatal("unsafe upstreams accepted")
		}
	}
	f := &dnsFixture{resolver: []byte(publicResolverFile)}
	r, err := configurePublicDNS(context.Background(), false, func() ([]byte, error) { return f.resolver, nil }, f)
	if err != nil || !r.Reused || f.writes != 0 {
		t.Fatal("static prepared resolver rewritten")
	}
}

func TestNetworkManagerDNSListsAcceptDocumentedSeparators(t *testing.T) {
	for _, data := range []string{"1.1.1.1,8.8.8.8\n", "1.1.1.1 | 8.8.8.8\n", "8.8.8.8\n1.1.1.1\n\n"} {
		if !publicActiveDNS([]byte(data)) {
			t.Fatal("valid public DNS list refused")
		}
	}
	for _, data := range []string{"1.1.1.1,8.8.8.8,10.0.2.3", "1.1.1.1 | 8.8.8.8 | ::1"} {
		if publicActiveDNS([]byte(data)) {
			t.Fatal("unexpected upstream accepted")
		}
	}
}
