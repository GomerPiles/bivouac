package rootnet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func syn() []byte {
	b := make([]byte, 54)
	copy(b[:6], gatewayMAC)
	copy(b[6:12], []byte{2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(b[12:], 0x800)
	ip := b[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:], 40)
	binary.BigEndian.PutUint32(ip[12:], 0xc0000202)
	copy(ip[16:], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))
	tcp := b[34:]
	binary.BigEndian.PutUint16(tcp, 40000)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	tcp[7], tcp[12], tcp[13] = 1, 0x50, 2
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	pseudo := make([]byte, 32)
	copy(pseudo, ip[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], 20)
	copy(pseudo[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:], checksum(pseudo))
	return b
}
func waitCount(t *testing.T, count *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for count.Load() != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if count.Load() != want {
		t.Fatalf("host dial count %d, want %d", count.Load(), want)
	}
}
func TestHostSocketAdmissionAndHostileEthernet(t *testing.T) {
	var calls atomic.Int32
	n, err := newNetwork(context.Background(), testMAC, options{allow: func(netip.Addr) bool { return true }, dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("fixture refused")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	good := syn()
	n.Input(good)
	waitCount(t, &calls, 1)
	tests := []func([]byte){
		func(b []byte) { b[6] ^= 1 },                                  // guest root spoofs its source MAC
		func(b []byte) { b[26] = 127 },                                // source IP spoof
		func(b []byte) { b[0] ^= 1 },                                  // destination Ethernet identity
		func(b []byte) { b[20] = 0x20 },                               // fragmented IPv4
		func(b []byte) { binary.BigEndian.PutUint16(b[12:], 0x86dd) }, // IPv6 independent of guest routes
		func(b []byte) { b[23] = 1 },                                  // external ICMP is deliberately not implemented
	}
	for _, mutate := range tests {
		packet := append([]byte(nil), good...)
		mutate(packet)
		n.Input(packet)
	}
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatal("spoofed/unsupported packet opened host socket")
	}
}
func TestPolicyChangeClosesExistingFlowAndRefusesNew(t *testing.T) {
	var allowed atomic.Bool
	allowed.Store(true)
	var calls atomic.Int32
	n, err := newNetwork(context.Background(), testMAC, options{allow: func(netip.Addr) bool { return allowed.Load() }, dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		a, b := net.Pipe()
		go func() { defer func() { _ = b.Close() }(); _, _ = io.Copy(b, b) }()
		return a, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, ctx := guestStack(t, n)
	c, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 443}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("control")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 7)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	allowed.Store(false)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(b); err == nil {
		t.Fatal("existing flow survived policy refusal")
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("policy refusal only reached the test deadline")
		}
	}
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if another, err := gonet.DialContextTCP(short, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 444}, ipv4.ProtocolNumber); err == nil {
		_ = another.Close()
		t.Fatal("new denied flow accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("denied flow reached host dial")
	}
}
func TestDNSAdmissionAndIPv6Suppression(t *testing.T) {
	n, err := newNetwork(context.Background(), testMAC, options{allow: func(a netip.Addr) bool { return a == netip.MustParseAddr("1.1.1.1") }, dnsExchange: testAddressResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	name, _ := dnsmessage.NewName("example.com.")
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		data, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 7}, Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}}}).Pack()
		var response dnsmessage.Message
		if response.Unpack(n.dnsResponse(data)) != nil {
			t.Fatal("DNS response invalid")
		}
		if len(response.Answers) != 0 {
			t.Fatal("DNS exposed private/IPv6 answer")
		}
	}
	if n.dnsResponse(make([]byte, 4097)) != nil {
		t.Fatal("oversize DNS query accepted")
	}
}
func TestDHCPProvidesOnlyVirtualRouterAndDNS(t *testing.T) {
	n, err := newNetwork(context.Background(), testMAC, options{settings: config.VZNetwork{MTU: 9000}, allow: func(netip.Addr) bool { t.Error("DHCP must never use host dial admission"); return false }})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	b := make([]byte, 42+244)
	for i := 0; i < 6; i++ {
		b[i] = 255
	}
	copy(b[6:12], n.mac)
	binary.BigEndian.PutUint16(b[12:], 0x800)
	ip := b[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:], uint16(len(b)-14)) //nolint:gosec // Fixed 286-byte test packet.
	binary.BigEndian.PutUint32(ip[16:], 0xffffffff)
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))
	u := b[34:]
	binary.BigEndian.PutUint16(u, 68)
	binary.BigEndian.PutUint16(u[2:], 67)
	binary.BigEndian.PutUint16(u[4:], uint16(len(u))) //nolint:gosec // Fixed 252-byte UDP fixture.
	boot := u[8:]
	boot[0], boot[1], boot[2] = 1, 1, 6
	copy(boot[28:], n.mac)
	binary.BigEndian.PutUint32(boot[236:], 0x63825363)
	copy(boot[240:], []byte{53, 1, 1, 255})
	n.Input(b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reply := n.Output(ctx)
	if len(reply) < 342 || binary.BigEndian.Uint32(reply[42+16:]) != 0xc0000202 {
		t.Fatal("DHCP did not offer fixed isolated guest address")
	}
	if !bytes.Contains(reply[282:], []byte{26, 2, 0x23, 0x28}) || n.link.MTU() != 9014 {
		t.Fatal("DHCP/link MTU not propagated")
	}
	if checksum(reply[14:34]) != 0 {
		t.Fatal("DHCP IPv4 checksum invalid")
	}
}

func TestVirtualDNSOverUDPAndTCP(t *testing.T) {
	n, err := newNetwork(context.Background(), testMAC, options{allow: func(a netip.Addr) bool { return a == netip.MustParseAddr("1.1.1.1") }, dnsExchange: testAddressResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	s, ctx := guestStack(t, n)
	for range cap(n.slots) {
		if !n.acquire() {
			t.Fatal("flow pool filled early")
		}
	}
	defer func() {
		for range cap(n.slots) {
			n.release()
		}
	}()
	if n.acquire() {
		n.release()
		t.Fatal("flow budget exceeded")
	}
	// DNS has its own budget even when all forwarding slots are occupied.
	name, _ := dnsmessage.NewName("example.com.")
	query, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 9}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	address := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: 53}
	udp, err := gonet.DialUDP(s, nil, &address, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := udp.Write(query); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 512)
	count, err := udp.Read(b)
	if err != nil {
		t.Fatal("virtual UDP DNS failed", err)
	}
	var response dnsmessage.Message
	if response.Unpack(b[:count]) != nil || len(response.Answers) != 1 {
		t.Fatal("UDP DNS answer invalid")
	}
	tcp, err := gonet.DialContextTCP(ctx, s, address, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	_ = tcp.SetDeadline(time.Now().Add(5 * time.Second))
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(query))) //nolint:gosec // Fixed small DNS question.
	if _, err := tcp.Write(append(h[:], query...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(tcp, h[:]); err != nil {
		t.Fatal("virtual TCP DNS failed", err)
	}
}

func TestPublicUDPForwardingUsesAdmittedHostSocket(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		b := make([]byte, 2048)
		for {
			count, peer, err := listener.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = listener.WriteTo(b[:count], peer)
		}
	}()
	var calls atomic.Int32
	n, err := newNetwork(context.Background(), testMAC, options{allow: func(a netip.Addr) bool { return a == netip.MustParseAddr("1.1.1.1") }, dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		calls.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, listener.LocalAddr().String())
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := guestStack(t, n)
	address := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 54545}
	c, err := gonet.DialUDP(s, nil, &address, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for range 3 {
		// Hosted race builds share CPUs with the rest of the suite. Bound each
		// exchange independently rather than spending one second on all three.
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("binary\x00datagram")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 128)
		count, err := c.Read(b)
		if err != nil || string(b[:count]) != "binary\x00datagram" {
			t.Fatalf("public UDP forwarding failed: read=%d err=%v", count, err)
		}
	}
	// These datagrams traverse the same virtual Ethernet/UDP path as the
	// positive control. Only the admitted control may create a host socket.
	for _, destination := range [][4]byte{{192, 0, 2, 1}, {127, 0, 0, 1}, {10, 0, 0, 1}, {169, 254, 169, 254}, {224, 0, 0, 251}} {
		for _, port := range []uint16{53, 5353, 54545} {
			address := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(destination), Port: port}
			blocked, err := gonet.DialUDP(s, nil, &address, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatal(err)
			}
			_ = blocked.SetDeadline(time.Now().Add(30 * time.Millisecond))
			_, err = blocked.Write([]byte("benign-negative-control"))
			if err != nil {
				_ = blocked.Close()
				t.Fatal(err)
			}
			_, err = blocked.Read(make([]byte, 64))
			_ = blocked.Close()
			if err == nil {
				t.Fatal("prohibited UDP destination replied")
			}
		}
	}
	if calls.Load() != 1 {
		t.Fatal("prohibited UDP traffic opened a host socket or the public flow lost its session")
	}
}

func TestARPClaimsOnlyGatewayNotGuestAddress(t *testing.T) {
	n, err := newNetwork(context.Background(), testMAC, options{allow: func(netip.Addr) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	packet := make([]byte, 42)
	for i := 0; i < 6; i++ {
		packet[i] = 255
	}
	copy(packet[6:12], n.mac)
	binary.BigEndian.PutUint16(packet[12:], 0x806)
	binary.BigEndian.PutUint16(packet[14:], 1)
	binary.BigEndian.PutUint16(packet[16:], 0x800)
	packet[18], packet[19] = 6, 4
	binary.BigEndian.PutUint16(packet[20:], 1)
	copy(packet[22:28], n.mac)
	// The initial DAD probe has source 0.0.0.0 and target the offered address.
	binary.BigEndian.PutUint32(packet[38:], 0xc0000202)
	n.Input(packet)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if frame := n.Output(ctx); frame != nil {
		t.Fatal("stack claimed guest address during DHCP duplicate-address detection")
	}
	binary.BigEndian.PutUint32(packet[38:], 0xc0000201)
	n.Input(packet)
	positive, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	frame := n.Output(positive)
	if len(frame) < 42 || binary.BigEndian.Uint16(frame[20:22]) != 2 || binary.BigEndian.Uint32(frame[28:32]) != 0xc0000201 {
		t.Fatal("gateway ARP positive control failed")
	}
}
