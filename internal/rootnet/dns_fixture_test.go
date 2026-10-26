package rootnet

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"
)

func testAddressResolver(lookup func(context.Context, string) ([]net.IPAddr, error)) func(context.Context, []byte) ([]byte, error) {
	return func(ctx context.Context, b []byte) ([]byte, error) {
		var m dnsmessage.Message
		if m.Unpack(b) != nil || len(m.Questions) != 1 {
			return nil, errors.New("fixture query invalid")
		}
		q := m.Questions[0]
		m.Response = true
		if q.Type != dnsmessage.TypeA {
			return m.Pack()
		}
		ips, err := lookup(ctx, q.Name.String())
		if err != nil {
			m.RCode = dnsmessage.RCodeServerFailure
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				m.RCode = dnsmessage.RCodeNameError
			}
		} else {
			for _, ip := range ips {
				if a := ip.IP.To4(); a != nil {
					m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{a[0], a[1], a[2], a[3]}}})
				}
			}
		}
		return m.Pack()
	}
}

func TestVirtualDNSAnswersBadVersionWithOPT(t *testing.T) {
	n, err := newNetwork(context.Background(), testMAC, options{dnsExchange: func(context.Context, []byte) ([]byte, error) {
		t.Error("unsupported EDNS version reached parent")
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	q := new(dns.Msg)
	q.SetQuestion("fixture.invalid.", dns.TypeA)
	q.SetEdns0(1232, true)
	q.IsEdns0().SetVersion(1)
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var m dns.Msg
	if m.Unpack(n.dnsResponse(raw)) != nil || m.Rcode != dns.RcodeBadVers || m.IsEdns0() == nil {
		t.Fatal("virtual DNS dropped unsupported EDNS")
	}
	if n.Stats().DNSInvalid != 0 {
		t.Fatal("valid unsupported version counted as malformed")
	}
}
