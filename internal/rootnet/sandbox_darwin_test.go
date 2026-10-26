package rootnet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/dnsproxy"
	"github.com/GomerPiles/bivouac/internal/macnetwork"
	"github.com/miekg/dns"
)

func TestNetworkSandbox(t *testing.T) {
	if os.Getenv("BIVOUAC_NETWORK_SANDBOX_TEST") == "1" {
		if err := ApplySandbox(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.ReadFile("/etc/hosts"); err == nil {
			t.Fatal("sandbox read host file")
		}
		if err := exec.Command("/usr/bin/true").Run(); err == nil {
			t.Fatal("sandbox executed a subprocess")
		}
		if _, err := macnetwork.Policy(); err != nil {
			t.Fatal("sandbox cannot read network policy:", err)
		}
		if os.Getenv("BIVOUAC_SANDBOX_PUBLIC_DNS_TEST") != "1" {
			return
		}
		// Public numeric sockets do not invoke the host resolver or Keychain.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		q := new(dns.Msg)
		q.SetQuestion("github.com.", dns.TypeA)
		query, _ := q.Pack()
		response, err := (dnsproxy.Resolver{Overrides: []string{"1.1.1.1"}}).Resolve(ctx, query)
		if err != nil || len(response) == 0 {
			t.Fatal("sandbox public DNS unavailable:", err)
		}
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestNetworkSandbox$")
	cmd.Env = []string{"BIVOUAC_NETWORK_SANDBOX_TEST=1", "HOME=/", "PATH=/usr/bin:/bin", "BIVOUAC_SANDBOX_PUBLIC_DNS_TEST=" + os.Getenv("BIVOUAC_SANDBOX_PUBLIC_DNS_TEST")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sandbox child: %v: %s", err, out)
	}
}

// Native denial requires a listening fixture and a positive parent connection,
// then an explicit EPERM from the sandbox. Timeouts/refusals cannot count.
func TestNetworkSandboxHostDenial(t *testing.T) {
	if os.Getenv("BIVOUAC_SANDBOX_HOST_FIXTURE") == "1" {
		if err := ApplySandbox(); err != nil {
			t.Fatal(err)
		}
		// UDP connect selects a route/socket without sending any packet.
		positive, err := net.DialTimeout("udp4", "192.0.2.55:9", time.Second)
		if err != nil {
			t.Fatal("sandbox outbound connect positive control failed")
		}
		_ = positive.Close()
		alias, err := net.DialTimeout("udp4", "127.0.0.2:9", time.Second)
		if os.Getenv("BIVOUAC_UNALIASED_LOOPBACK") == "1" {
			if err != nil {
				t.Fatal("unconfigured loopback connect unexpectedly denied")
			}
			_ = alias.Close()
		} else if err == nil {
			_ = alias.Close()
		}
		for _, address := range strings.Split(os.Getenv("BIVOUAC_SANDBOX_FIXTURES"), ",") {
			c, err := net.DialTimeout("tcp4", address, time.Second) //nolint:gosec // Parent-selected local fixture; this child must receive EPERM.
			if err == nil {
				_ = c.Close()
				t.Fatal("sandbox reached host fixture")
			}
			if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
				t.Fatal("host denial was not an explicit permission error")
			}
		}
		if _, err := macnetwork.Policy(); err != nil {
			t.Fatal("sandbox route sysctl refresh failed")
		}
		t.Log("explicit denial: IPv4 loopback and bound current host IPv4 interfaces; route sysctl remains available; non-local UDP connect succeeds without sending")
		return
	}
	addresses := map[string]bool{"127.0.0.1": true}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal("interface inventory unavailable")
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal("interface inventory unavailable")
		}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsUnspecified() {
				addresses[prefix.Addr().String()] = true
			}
		}
	}
	unalias := "1"
	if addresses["127.0.0.2"] {
		unalias = "0"
	}
	var fixtures []string
	for address := range addresses {
		l, err := net.Listen("tcp4", net.JoinHostPort(address, "0"))
		if err != nil {
			if errors.Is(err, syscall.EADDRNOTAVAIL) {
				t.Log("one enumerated address could not bind; excluded from denial evidence")
				continue
			}
			t.Fatal("cannot bind positive host fixture")
		}
		defer func() { _ = l.Close() }()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		c, err := net.DialTimeout("tcp4", l.Addr().String(), time.Second)
		if err != nil {
			t.Fatal("host fixture positive control failed")
		}
		_ = c.Close()
		fixtures = append(fixtures, l.Addr().String())
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestNetworkSandboxHostDenial$", "-test.v")
	cmd.Env = []string{"HOME=/", "BIVOUAC_SANDBOX_HOST_FIXTURE=1", "BIVOUAC_UNALIASED_LOOPBACK=" + unalias, "BIVOUAC_SANDBOX_FIXTURES=" + strings.Join(fixtures, ",")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native host denial fixture failed: %v: %s", err, out)
	}
	t.Logf("%s", out)
}

// Only the opt-in hosted CI step may change host addresses. Keep these subtests
// serial, and refuse existing aliases so cleanup removes only our own fixtures.
func TestNetworkSandboxAliases(t *testing.T) {
	if os.Getenv("BIVOUAC_CI_SANDBOX_ALIASES") != "1" {
		t.Skip("requires BIVOUAC_CI_SANDBOX_ALIASES=1 on a hosted macOS runner")
	}
	addresses := []string{"127.0.0.2", "203.0.113.5"}
	if order := os.Getenv("BIVOUAC_SANDBOX_ALIAS_CHILD"); order != "" {
		if err := ApplySandbox(); err != nil {
			t.Fatal(err)
		}
		ready := os.NewFile(3, "sandbox-ready")
		if _, err := ready.Write([]byte{1}); err != nil {
			t.Fatal("sandbox readiness signal failed:", err)
		}
		_ = ready.Close()
		var proceed [1]byte
		if _, err := io.ReadFull(os.Stdin, proceed[:]); err != nil || proceed[0] != 1 {
			t.Fatal("sandbox alias fixture was not released")
		}
		// UDP connect and close never send packets, including the positive control.
		positive, err := net.DialTimeout("udp4", "192.0.2.55:9", time.Second)
		if err != nil {
			t.Fatal("sandbox outbound connect positive control failed:", err)
		}
		_ = positive.Close()
		t.Logf("event=sandbox_alias order=%s phase=sandboxed address=192.0.2.55 udp_connect=allowed packets_sent=0", order)
		for _, address := range addresses {
			c, err := net.DialTimeout("udp4", net.JoinHostPort(address, "9"), time.Second)
			if err == nil {
				_ = c.Close()
				t.Errorf("event=sandbox_alias order=%s phase=sandboxed address=%s udp_connect=allowed want=denied packets_sent=0", order, address)
				continue
			}
			permission := "EPERM"
			if errors.Is(err, syscall.EACCES) {
				permission = "EACCES"
			} else if !errors.Is(err, syscall.EPERM) {
				t.Errorf("event=sandbox_alias order=%s phase=sandboxed address=%s udp_connect=error want=permission_denied error=%q", order, address, err)
				continue
			}
			t.Logf("event=sandbox_alias order=%s phase=sandboxed address=%s udp_connect=denied errno=%s packets_sent=0", order, address, permission)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "/usr/bin/true").Run()
	cancel()
	if err != nil {
		t.Fatal("alias test requires passwordless sudo -n on a hosted macOS runner:", err)
	}
	for _, order := range []string{"before_sandbox", "after_sandbox"} {
		t.Run(order, func(t *testing.T) {
			for _, address := range addresses {
				if sandboxAliasPresent(t, address) {
					t.Fatalf("refusing to alter pre-existing alias %s", address)
				}
			}
			addAliases := func() {
				for _, address := range addresses {
					// Register before attempting the mutation, so a failed or timed-out
					// ifconfig cannot leave a partially added fixture behind.
					t.Cleanup(func() {
						if err := sandboxAliasCommand("-alias", address); err != nil {
							t.Errorf("alias cleanup failed for %s (sudo -n ifconfig): %v", address, err)
						}
						if sandboxAliasPresent(t, address) {
							t.Errorf("alias cleanup left %s configured", address)
							return
						}
						t.Logf("event=sandbox_alias order=%s phase=cleanup address=%s configured=false", order, address)
					})
					if err := sandboxAliasCommand("alias", address, "netmask", "255.255.255.255"); err != nil {
						t.Fatalf("alias setup failed for %s (requires sudo -n ifconfig): %v", address, err)
					}
					if !sandboxAliasPresent(t, address) {
						t.Fatalf("alias setup did not configure %s", address)
					}
					// Binding proves this is a configured local address; the parent
					// connect proves routing works without sending a UDP datagram.
					listener, err := net.ListenPacket("udp4", net.JoinHostPort(address, "0"))
					if err != nil {
						t.Fatal("unsandboxed alias bind failed:", err)
					}
					c, err := net.DialTimeout("udp4", listener.LocalAddr().String(), time.Second)
					_ = listener.Close()
					if err != nil {
						t.Fatal("unsandboxed alias connect positive control failed:", err)
					}
					_ = c.Close()
					t.Logf("event=sandbox_alias order=%s phase=unsandboxed address=%s local_bind=ok udp_connect=allowed packets_sent=0", order, address)
				}
			}
			if order == "before_sandbox" {
				addAliases()
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ready, signal, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ready.Close() }()
			defer func() { _ = signal.Close() }()
			if err := ready.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestNetworkSandboxAliases$", "-test.v")
			cmd.Env = []string{"HOME=/", "BIVOUAC_CI_SANDBOX_ALIASES=1", "BIVOUAC_SANDBOX_ALIAS_CHILD=" + order}
			cmd.ExtraFiles = []*os.File{signal}
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			release, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = release.Close() }()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				cancel()
				if !waited {
					_ = cmd.Wait()
				}
			}()
			_ = signal.Close()
			var activated [1]byte
			if _, err := io.ReadFull(ready, activated[:]); err != nil || activated[0] != 1 {
				cancel()
				waitErr := cmd.Wait()
				waited = true
				t.Fatalf("sandbox readiness failed: read=%v child=%v output=%s", err, waitErr, &output)
			}
			t.Logf("event=sandbox_alias order=%s phase=sandbox_ready", order)
			if order == "after_sandbox" {
				addAliases()
			}
			if _, err := release.Write([]byte{1}); err != nil {
				t.Fatal("sandbox alias fixture release failed:", err)
			}
			err = cmd.Wait()
			waited = true
			t.Logf("%s", &output)
			if err != nil {
				t.Fatal("sandbox alias child failed:", err)
			}
		})
	}
}

func sandboxAliasPresent(t *testing.T, address string) bool {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("alias inventory unavailable:", err)
	}
	for _, a := range addresses {
		prefix, err := netip.ParsePrefix(a.String())
		if err == nil && prefix.Addr().String() == address {
			return true
		}
	}
	return false
}

func sandboxAliasCommand(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/bin/sudo", append([]string{"-n", "/sbin/ifconfig", "lo0"}, args...)...).Run()
}
