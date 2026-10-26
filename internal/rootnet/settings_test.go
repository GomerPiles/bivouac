package rootnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
)

func TestRefusalCountersAndPendingHandshakeCeiling(t *testing.T) {
	for _, kind := range []string{"limit", "denied", "dial"} {
		t.Run(kind, func(t *testing.T) {
			n, err := newNetwork(context.Background(), testMAC, options{settings: config.VZNetwork{MaxFlows: 1}, allow: func(netip.Addr) bool { return kind != "denied" }, dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("fixture refused") }})
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			if kind == "limit" {
				if !n.acquire() {
					t.Fatal("first slot unavailable")
				}
				defer n.release()
			}
			n.Input(syn())
			deadline := time.Now().Add(time.Second)
			var count uint64
			for time.Now().Before(deadline) {
				s := n.Stats()
				switch kind {
				case "limit":
					count = s.FlowLimit
				case "denied":
					count = s.AdmissionDenied
				case "dial":
					count = s.DialFailed
				}
				if count != 0 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if count != 1 {
				t.Fatal("refused flow not counted")
			}
			if kind != "limit" {
				n.Close()
				s := n.Stats()
				if s.ActivePublicTCP+s.ActiveUDP+s.ActiveCache != 0 {
					t.Fatal("refused flow retained active gauges")
				}
			}
		})
	}
	started := make(chan struct{})
	release := make(chan struct{})
	n, err := newNetwork(context.Background(), testMAC, options{settings: config.VZNetwork{MaxFlows: 1}, allow: func(netip.Addr) bool { return true }, dial: func(context.Context, string, string) (net.Conn, error) {
		close(started)
		<-release
		return nil, errors.New("fixture refused")
	}})
	if err != nil {
		t.Fatal(err)
	}
	n.Input(syn())
	<-started
	if len(n.slots) != 1 || n.acquire() {
		t.Fatal("pending handshake outside flow budget")
	}
	close(release)
	n.Close()
}
func TestNetworkDefaultsAndMTUBounds(t *testing.T) {
	n, err := newNetwork(context.Background(), testMAC, options{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if cap(n.slots) != 4096 || n.options.tcpIdle != 24*time.Hour || n.options.udpIdle != time.Minute || n.link.MTU() != 16384+14 {
		t.Fatal("NAT-like defaults not applied")
	}
	before := n.Stats().Oversized
	n.Input(make([]byte, n.options.settings.MTU+15))
	if n.Stats().Oversized != before+1 {
		t.Fatal("oversize input admitted")
	}
	n2, err := newNetwork(context.Background(), testMAC, options{settings: config.VZNetwork{MTU: 65535}})
	if err != nil {
		t.Fatal(err)
	}
	defer n2.Close()
	if n2.link.MTU() != 65549 {
		t.Fatal("max Ethernet frame bound incorrect")
	}
	buffer := n.udpGuestBuffers.Get().(*[]byte)
	if len(*buffer) != n.options.settings.MTU-28+1 {
		t.Fatal("idle UDP buffers do not scale with MTU")
	}
	n.udpGuestBuffers.Put(buffer)
}
