package rootnet

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cachelink"
	"github.com/GomerPiles/bivouac/internal/config"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const testMAC = "02:00:00:00:00:02"

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
func guestStack(t testing.TB, n *Network) (*stack.Stack, context.Context) {
	t.Helper()
	return guestStackMode(t, n, false)
}
func guestStackMode(t testing.TB, n *Network, socket bool) (*stack.Stack, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	mac, _ := net.ParseMAC(testMAC)
	link := channel.New(256, uint32(n.options.settings.MTU+14), tcpip.LinkAddress(mac)) //nolint:gosec // Validated MTU is 1500..65535.
	guestWire := newPacketLink(ctx, link, dataQueueFrames, controlQueueFrames)
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	if e := s.CreateNIC(1, ethernet.New(guestWire)); e != nil {
		t.Fatal(e)
	}
	_ = s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{192, 0, 2, 2}), PrefixLen: 24}}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, Gateway: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), NIC: 1}})
	_ = s.AddStaticNeighbor(1, ipv4.ProtocolNumber, tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), tcpip.LinkAddress(gatewayMAC))
	var transport net.Conn
	var wg sync.WaitGroup
	if socket {
		router, guest := socketFixture(t)
		transport = guest
		wg.Go(func() { _ = n.Serve(router) })
	}
	wg.Go(func() {
		for {
			packet := guestWire.read(ctx)
			if packet == nil {
				return
			}
			if transport != nil {
				if _, err := transport.Write(packet); err != nil {
					return
				}
			} else {
				n.Input(packet)
			}
		}
	})
	wg.Go(func() {
		for {
			var b []byte
			if transport != nil {
				buffer := make([]byte, n.options.settings.MTU+15)
				count, err := readDatagram(transport, buffer)
				if err != nil {
					return
				}
				b = buffer[:count]
			} else {
				b = n.Output(ctx)
			}
			if b == nil {
				return
			}
			p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
			link.InjectInbound(0, p)
			p.DecRef()
		}
	})
	t.Cleanup(func() {
		cancel()
		if transport != nil {
			_ = transport.Close()
		}
		n.Close()
		s.Close()
		link.Close()
		wg.Wait()
		s.Wait()
	})
	return s, ctx
}
func BenchmarkDownload(b *testing.B) {
	for _, mtu := range []int{1500, 9000, 65535} {
		b.Run(fmt.Sprint(mtu), func(b *testing.B) { benchmarkDownload(b, mtu, false, false, 0) })
	}
}
func BenchmarkServeDownload(b *testing.B) {
	for _, mtu := range []int{1500, 9000, 65535} {
		b.Run(fmt.Sprint(mtu), func(b *testing.B) { benchmarkDownload(b, mtu, true, false, 0) })
	}
}
func BenchmarkCacheSendBuffer(b *testing.B) {
	for _, mtu := range []int{1500, 9000, 65535} {
		b.Run(fmt.Sprint(mtu), func(b *testing.B) {
			for _, size := range []int{64 << 10, 1 << 20, -1} {
				b.Run(fmt.Sprint(size), func(b *testing.B) { benchmarkDownload(b, mtu, true, true, size) })
			}
		})
	}
}
func benchmarkDownload(b *testing.B, mtu int, socket, cache bool, sendBuffer int) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	const size = 128 << 20
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.CopyN(c, zeroReader{}, size) }()
		}
	}()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}
	o := options{settings: config.VZNetwork{MTU: mtu}, allow: func(netip.Addr) bool { return true }, dial: dial, cacheSendBuffer: sendBuffer}
	target := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 443}
	if cache {
		o.cacheDial = func(ctx context.Context, _ cachelink.Kind) (net.Conn, error) { return dial(ctx, "tcp4", "") }
		target.Addr = tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
		target.Port = cachelink.Port
	}
	n, err := newNetwork(context.Background(), testMAC, o)
	if err != nil {
		b.Fatal(err)
	}
	s, ctx := guestStackMode(b, n, socket)
	b.SetBytes(size)
	b.ResetTimer()
	for range b.N {
		c, err := gonet.DialContextTCP(ctx, s, target, ipv4.ProtocolNumber)
		if err != nil {
			b.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		count, err := io.CopyN(io.Discard, c, size)
		_ = c.Close()
		if err != nil || count != size {
			b.Fatalf("bounded transfer: %d %v", count, err)
		}
	}
}

// Both TCP directions must progress together, including while a peer reads
// slowly. This exercises protocol locks and ACKs rather than only queue APIs.
func TestConcurrentFullDuplexWithSlowReader(t *testing.T) {
	const flows, size = 16, 1 << 20
	results := make(chan error, 4*flows)
	start := make(chan struct{})
	var workers sync.WaitGroup
	copyExact := func(dst io.Writer, src io.Reader) {
		defer workers.Done()
		<-start
		n, err := io.CopyN(dst, src, size)
		if err == nil && n != size {
			err = io.ErrUnexpectedEOF
		}
		results <- err
	}
	n, err := newNetwork(context.Background(), testMAC, options{
		allow: func(netip.Addr) bool { return true },
		dial: func(context.Context, string, string) (net.Conn, error) {
			a, b := net.Pipe()
			t.Cleanup(func() { _ = b.Close() })
			_ = b.SetDeadline(time.Now().Add(20 * time.Second))
			workers.Add(2)
			go copyExact(b, zeroReader{})
			go copyExact(io.Discard, b)
			return a, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, ctx := guestStack(t, n)
	for i := range flows {
		c, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 443}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
		workers.Add(2)
		go copyExact(c, zeroReader{})
		var reader io.Reader = c
		if i == 0 {
			reader = slowReader{Reader: c}
		}
		go copyExact(io.Discard, reader)
	}
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("full-duplex transfer failed: %v; counters=%+v", err, n.Stats())
		}
	}
}

type slowReader struct{ io.Reader }

func (r slowReader) Read(b []byte) (int, error) {
	time.Sleep(time.Millisecond)
	if len(b) > 16<<10 {
		b = b[:16<<10]
	}
	return r.Reader.Read(b)
}
