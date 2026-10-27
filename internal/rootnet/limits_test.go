package rootnet

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestDNSCodesAndUnsupportedTypes(t *testing.T) {
	for _, kind := range []string{"missing", "failure", "private", "unsupported"} {
		n, err := newNetwork(context.Background(), testMAC, options{allow: func(netip.Addr) bool { return false }, dnsExchange: testAddressResolver(func(context.Context, string) ([]net.IPAddr, error) {
			if kind == "private" {
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
			}
			return nil, &net.DNSError{IsNotFound: kind == "missing"}
		})})
		if err != nil {
			t.Fatal(err)
		}
		name, _ := dnsmessage.NewName("example.invalid.")
		typ := dnsmessage.TypeA
		if kind == "unsupported" {
			typ = dnsmessage.TypeTXT
		}
		query, _ := (&dnsmessage.Message{Questions: []dnsmessage.Question{{Name: name, Type: typ, Class: dnsmessage.ClassINET}}}).Pack()
		var response dnsmessage.Message
		if response.Unpack(n.dnsResponse(query)) != nil {
			t.Fatal("invalid response")
		}
		want := dnsmessage.RCodeNameError
		if kind == "failure" {
			want = dnsmessage.RCodeServerFailure
		}
		if kind == "unsupported" {
			want = dnsmessage.RCodeSuccess
		}
		stats := n.Stats()
		if kind == "failure" && stats.DNSFailed != 1 || kind == "private" && stats.DNSRefused != 1 {
			t.Fatal("DNS refusal/failure counter missing")
		}
		n.Close()
		if response.RCode != want || len(response.Answers) != 0 {
			t.Fatal("DNS error/empty-answer semantics changed")
		}
	}
}
func TestIdleTCPLimitReleasesFlow(t *testing.T) {
	n, err := newNetwork(context.Background(), testMAC, options{tcpIdle: 50 * time.Millisecond, allow: func(netip.Addr) bool { return true }, dial: func(context.Context, string, string) (net.Conn, error) {
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
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("silent TCP flow retained indefinitely")
	}
	deadline := time.Now().Add(time.Second)
	for len(n.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(n.slots) != 0 {
		t.Fatal("idle TCP flow retained slot")
	}
}

func TestSingleExchangeUDPBurstDoesNotExhaustForwarding(t *testing.T) {
	n, err := newNetwork(context.Background(), testMAC, options{settings: config.VZNetwork{MaxFlows: 128}, allow: func(netip.Addr) bool { return true }, dial: func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { defer func() { _ = b.Close() }(); _, _ = io.Copy(b, b) }()
		return a, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := guestStack(t, n)
	for index := 0; index < 128+32; index++ {
		address := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 53}
		if index%2 == 1 {
			address.Port = 123
		}
		c, err := gonet.DialUDP(s, nil, &address, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = c.Write([]byte("single-exchange"))
		if err != nil {
			_ = c.Close()
			t.Fatal(err)
		}
		data := make([]byte, 64)
		count, err := c.Read(data)
		_ = c.Close()
		if err != nil || string(data[:count]) != "single-exchange" {
			t.Fatal("single-exchange burst exhausted forwarding budget", err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for len(n.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(n.slots) != 0 {
		t.Fatal("completed DNS/NTP exchanges retained flow slots")
	}
}

func TestUDPActivityRefreshesBothDirections(t *testing.T) {
	result := make(chan error, 1)
	received := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	n, err := newNetwork(context.Background(), testMAC, options{udpIdle: time.Second, allow: func(netip.Addr) bool { return true }, dial: func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			defer func() { _ = b.Close() }()
			_ = b.SetDeadline(time.Now().Add(10 * time.Second))
			var one [1]byte
			for range 6 {
				if _, err := io.ReadFull(b, one[:]); err != nil {
					result <- err
					return
				}
				received <- struct{}{}
			}
			_, err := b.Write([]byte("reply"))
			result <- err
			// Keep the fixture open until the guest receives its datagram. An artificial
			// EOF must not race the assertion or stand in for an idle expiry.
			<-release
		}()
		return a, nil
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
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	for i := range 6 {
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-received:
		case err := <-result:
			t.Fatal("fixture stopped receiving", err)
		case <-time.After(5 * time.Second):
			t.Fatal("fixture did not receive datagram")
		}
		if i < 5 {
			time.Sleep(250 * time.Millisecond)
		}
	}
	b := make([]byte, 16)
	count, err := c.Read(b)
	if err != nil || string(b[:count]) != "reply" {
		t.Fatal("outbound activity did not keep reply direction alive", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
