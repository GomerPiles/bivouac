package rootnet

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestLargeUpstreamUDPAtMTU1500(t *testing.T) {
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	var allocations atomic.Int32
	reply := bytes.Repeat([]byte{0xa5}, 3000)
	go func() {
		var one [1]byte
		_, peer, err := l.ReadFrom(one[:])
		if err == nil {
			_, _ = l.WriteTo(reply, peer)
		}
	}()
	n, err := newNetwork(context.Background(), testMAC, options{settings: config.VZNetwork{MTU: 1500}, allow: func(netip.Addr) bool { return true }, dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, l.LocalAddr().String())
	}})
	if err != nil {
		t.Fatal(err)
	}
	n.udpBuffers.New = func() any { allocations.Add(1); b := make([]byte, 65507); return &b }
	s, _ := guestStack(t, n)
	target := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 53}
	c, err := gonet.DialUDP(s, nil, &target, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4096)
	count, err := c.Read(data)
	if err != nil || !bytes.Equal(data[:count], reply) {
		t.Fatal("large UDP reply was not reassembled", count, err)
	}
	if allocations.Load() == 0 {
		t.Fatal("upstream buffer fixture not exercised")
	}
}
func TestIdleUDPWaitDoesNotBorrowPayloadBuffer(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native UDP readiness polling is macOS/Linux only")
	}
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	received := make(chan struct{})
	go func() {
		var b [1]byte
		if _, _, err := l.ReadFrom(b[:]); err == nil {
			close(received)
		}
	}()
	n, err := newNetwork(context.Background(), testMAC, options{allow: func(netip.Addr) bool { return true }, dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, l.LocalAddr().String())
	}})
	if err != nil {
		t.Fatal(err)
	}
	var allocations atomic.Int32
	n.udpBuffers.New = func() any { allocations.Add(1); b := make([]byte, 65507); return &b }
	s, _ := guestStack(t, n)
	target := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 54545}
	c, err := gonet.DialUDP(s, nil, &target, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream fixture did not receive")
	}
	if allocations.Load() != 0 {
		t.Fatal("idle upstream reader borrowed payload buffer")
	}
}
func TestBudgetDerivedTCPBufferRanges(t *testing.T) {
	for _, settings := range []config.VZNetwork{{}, {MemoryMB: 2048, MaxFlows: 1024}, {MemoryMB: 1, MaxFlows: 65536}, {MemoryMB: 65536, MaxFlows: 1}} {
		n, err := newNetwork(context.Background(), testMAC, options{settings: settings})
		if err != nil {
			t.Fatal(err)
		}
		var send tcpip.TCPSendBufferSizeRangeOption
		var receive tcpip.TCPReceiveBufferSizeRangeOption
		if n.s.TransportProtocolOption(tcp.ProtocolNumber, &send) != nil || n.s.TransportProtocolOption(tcp.ProtocolNumber, &receive) != nil {
			t.Fatal("TCP buffer policy unavailable")
		}
		want := settings.TCPBufferLimit()
		if send.Max != want || send.Default != want || receive.Max != want || receive.Default != want {
			t.Fatal("TCP stack exceeded budget-derived maximum")
		}
		n.Close()
	}
}
