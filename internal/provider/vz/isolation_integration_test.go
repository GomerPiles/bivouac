//go:build integration

package vz

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/macnetwork"
	"github.com/GomerPiles/bivouac/internal/rootnet"
)

// Only our temporary listeners and an explicitly owner-selected peer are probed.
// No private address range is scanned, and no production endpoint is selected.
func validateGuestIsolation(t *testing.T, ctx context.Context, p *Provider, name string) {
	t.Helper()
	type hostTarget struct{ host, port string }
	var listeners []net.Listener
	var workers sync.WaitGroup
	var accepted atomic.Int64
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
		workers.Wait()
	}()
	listen := func(host string) hostTarget {
		listener, err := net.Listen("tcp4", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatal("temporary owned host listener unavailable")
		}
		listeners = append(listeners, listener)
		workers.Go(func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				_ = c.Close()
			}
		})
		_, port, _ := net.SplitHostPort(listener.Addr().String())
		return hostTarget{host, port}
	}
	loopback := listen("127.0.0.1")
	// Guest loopback belongs to the guest and may host legitimate services.
	// Probe the virtual gateway for accidental host-loopback mapping instead.
	var targets []hostTarget

	route, err := p.output(ctx, name, []string{"/sbin/route", "-n", "get", "default"}, nil)
	if err != nil {
		t.Fatal("guest default route unavailable")
	}
	for _, line := range strings.Split(string(route), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "gateway:" && net.ParseIP(f[1]).To4() != nil {
			if f[1] != rootnet.Gateway {
				t.Fatal("guest default gateway is not the fixed virtual endpoint")
			}
			targets = append(targets, hostTarget{f[1], loopback.port})
		}
	}
	if len(targets) == 0 {
		t.Fatal("guest IPv4 gateway unavailable")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, intf := range interfaces {
		addresses, err := intf.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range addresses {
			ip, _, err := net.ParseCIDR(a.String())
			if err == nil && ip.To4() != nil && !ip.IsLoopback() {
				targets = append(targets, listen(ip.String()))
			}
		}
	}
	// Every physical-host address uses a port allocated by our own listener,
	// with a successful host-side control. No unrelated service port is probed.
	for _, l := range listeners {
		control, err := net.DialTimeout("tcp4", l.Addr().String(), time.Second)
		if err != nil {
			t.Fatal("temporary host listener positive control failed")
		}
		_ = control.Close()
	}
	expected := int64(len(listeners))
	deadline := time.Now().Add(time.Second)
	for accepted.Load() != expected && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if accepted.Load() != expected {
		t.Fatal("temporary host listener controls not accepted")
	}
	blocked := func(argv []string) {
		_, err := p.output(ctx, name, argv, nil)
		var exit *guestagent.ExitError
		if ctx.Err() != nil || !errors.As(err, &exit) || exit.Code != 1 {
			t.Fatal("guest command did not prove destination refusal")
		}
	}

	// Public DNS + HTTPS must work both as the runner user and as guest root.
	for _, privileged := range []bool{false, true} {
		prefix := []string{}
		if privileged {
			prefix = []string{"sudo", "-n"}
		}
		public := append(append([]string{}, prefix...), "/usr/bin/curl", "--noproxy", "*", "--fail", "--silent", "--connect-timeout", "5", "--max-time", "20", "--output", "/dev/null", "https://github.com")
		if _, err := p.output(ctx, name, public, nil); err != nil {
			t.Fatal("public guest DNS/HTTPS failed")
		}
		positive := append(append([]string{}, prefix...), "/usr/bin/nc", "-4", "-G", "2", "-z", "github.com", "443")
		if _, err := p.output(ctx, name, positive, nil); err != nil {
			t.Fatal("public nc execution control failed")
		}
		for _, target := range targets {
			probe := append(append([]string{}, prefix...), "/usr/bin/nc", "-4", "-G", "2", "-z", target.host, target.port)
			blocked(probe)
		}
		for _, target := range []string{"169.254.169.254", "169.254.170.2"} {
			probe := append(append([]string{}, prefix...), "/usr/bin/nc", "-4", "-G", "2", "-z", target, "9")
			blocked(probe)
		}
		probe := append(append([]string{}, prefix...), "/usr/bin/nc", "-6", "-G", "2", "-z", "2606:4700:4700::1111", "443")
		blocked(probe)
		if _, err := p.output(ctx, name, positive, nil); err != nil {
			t.Fatal("public nc control failed after denial probes")
		}
	}
	if accepted.Load() != expected {
		t.Fatal("host listener observed a prohibited guest connection")
	}
	if peer := os.Getenv("BIVOUAC_VZ_TEST_PEER"); peer != "" {
		host, port, err := net.SplitHostPort(peer)
		n, e := strconv.Atoi(port)
		if err != nil || e != nil || n < 1 || n > 65535 || net.ParseIP(host).To4() == nil {
			t.Fatal("peer must be an explicit owner-controlled IPv4 endpoint")
		}
		policy, err := macnetwork.Policy()
		if err != nil || macnetwork.Allows(policy, netip.MustParseAddr(host)) {
			t.Fatal("owner-controlled peer must be within the denied networks")
		}
		control, err := net.DialTimeout("tcp", peer, 2*time.Second) //nolint:gosec // The opt-in private peer is explicitly owner-controlled; this lab intentionally probes it.
		if err != nil {
			t.Fatal("owner-controlled peer positive control failed")
		}
		_ = control.Close()
		blocked([]string{"sudo", "-n", "/usr/bin/nc", "-4", "-G", "2", "-z", host, port})
	} else {
		t.Log("owner-controlled private peer remains unverified")
	}
	// Recreate the provider to exercise durable ownership + live-helper rootless proof.
	adopted, err := New(p.name, p.cfg, p.controllerID, string(p.store), p.rt, nil)
	if err != nil {
		t.Fatal(err)
	}
	adopted.SetRecords(p.records)
	if err := adopted.runnerIsolation(name); err != nil {
		t.Fatal("rootless guest failed adoption proof")
	}
}
