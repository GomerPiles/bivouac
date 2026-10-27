package rootnet

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cachelink"
	"github.com/GomerPiles/bivouac/internal/config"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestActiveFlowGaugesIncludePendingAndReleaseOnClose(t *testing.T) {
	for _, kind := range []string{"tcp", "udp", "cache", "crl"} {
		t.Run(kind, func(t *testing.T) {
			started, release := make(chan struct{}, 1), make(chan struct{})
			peers := make(chan net.Conn, 1)
			dial := func(ctx context.Context) (net.Conn, error) {
				started <- struct{}{}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-release:
				}
				a, b := net.Pipe()
				peers <- b
				return a, nil
			}
			n, err := newNetwork(context.Background(), testMAC, options{
				settings: config.VZNetwork{MaxFlows: 1}, allow: func(netip.Addr) bool { return true },
				dial:      func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
				cacheDial: func(ctx context.Context, _ cachelink.Kind) (net.Conn, error) { return dial(ctx) },
			})
			if err != nil {
				t.Fatal(err)
			}
			s, parent := guestStack(t, n)
			ctx, cancel := context.WithTimeout(parent, 5*time.Second)
			defer cancel()
			target := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 443}
			if kind == "cache" || kind == "crl" {
				target.Addr = tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
				target.Port = cachelink.Port
			}
			if kind == "crl" {
				target.Port = cachelink.RevocationPort
			}
			connected := make(chan net.Conn, 1)
			errs := make(chan error, 1)
			if kind == "udp" {
				c, err := gonet.DialUDP(s, nil, &target, ipv4.ProtocolNumber)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = c.Close() }()
				if _, err := c.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
			} else {
				go func() {
					c, err := gonet.DialContextTCP(ctx, s, target, ipv4.ProtocolNumber)
					if err != nil {
						errs <- err
						return
					}
					connected <- c
				}()
			}
			select {
			case <-started:
			case err := <-errs:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal("dial never acquired a slot")
			}
			assertGauge := func() {
				t.Helper()
				report := n.Stats()
				wantTCP, wantUDP, wantCache := uint64(0), uint64(0), uint64(0)
				switch kind {
				case "tcp":
					wantTCP = 1
				case "udp":
					wantUDP = 1
				case "cache":
					wantCache = 1
				}
				if report.ActivePublicTCP != wantTCP || report.ActiveUDP != wantUDP || report.ActiveCache != wantCache {
					t.Fatalf("incorrect %s gauges: %+v", kind, report)
				}
			}
			assertGauge() // upstream is deliberately blocked before returning a connection
			if kind != "crl" && n.acquire() {
				n.release()
				t.Fatal("pending flow did not consume the general ceiling")
			}
			close(release)
			var peer net.Conn
			select {
			case peer = <-peers:
			case <-ctx.Done():
				t.Fatal("upstream did not establish")
			}
			defer func() { _ = peer.Close() }()
			if kind == "udp" {
				_ = peer.SetReadDeadline(time.Now().Add(time.Second))
				var one [1]byte
				if _, err := io.ReadFull(peer, one[:]); err != nil {
					t.Fatal("UDP relay did not establish", err)
				}
			} else {
				select {
				case c := <-connected:
					defer func() { _ = c.Close() }()
				case err := <-errs:
					t.Fatal(err)
				case <-ctx.Done():
					t.Fatal("guest handshake did not finish")
				}
			}
			assertGauge()
			n.Close()
			report := n.Stats()
			if report.ActivePublicTCP+report.ActiveUDP+report.ActiveCache != 0 {
				t.Fatal("close retained active gauges", report)
			}
		})
	}
}

func TestPendingFlowGaugeReleasedAfterDialFailure(t *testing.T) {
	started := make(chan struct{})
	n, err := newNetwork(context.Background(), testMAC, options{allow: func(netip.Addr) bool { return true }, dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.Input(syn())
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("pending TCP dial not started")
	}
	if n.Stats().ActivePublicTCP != 1 {
		t.Fatal("pending TCP missing from gauge")
	}
	n.Close() // cancellation must release even a dial that never established
	if n.Stats().ActivePublicTCP != 0 {
		t.Fatal("canceled pending TCP gauge retained")
	}
}
