package macnetwork

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestResolverLiteralDoesNotRequireNetwork(t *testing.T) {
	for _, servers := range [][]string{nil, {"127.0.0.1"}} {
		ips, err := Resolver(servers)(context.Background(), "192.0.2.20")
		if err != nil || len(ips) != 1 || ips[0].IP.String() != "192.0.2.20" {
			t.Fatal("literal lookup failed")
		}
	}
}

func TestOverrideQueriesInsteadOfHostNameSources(t *testing.T) {
	calls := 0
	lookup := resolverLookup(func(_ context.Context, raw []byte) ([]byte, error) {
		calls++
		var q dns.Msg
		if q.Unpack(raw) != nil || q.Question[0].Name != "localhost." {
			t.Fatal("override query invalid")
		}
		m := new(dns.Msg)
		m.SetReply(&q)
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "localhost.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(1, 1, 1, 1)}, &dns.A{Hdr: dns.RR_Header{Name: "localhost.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(10, 0, 0, 1)}}
		return m.Pack()
	})
	ips, err := lookup(context.Background(), "localhost")
	if err != nil || calls != 1 || len(ips) != 2 {
		t.Fatal("override used host name sources or omitted answers")
	}
}
