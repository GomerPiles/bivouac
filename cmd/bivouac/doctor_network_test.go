package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestDoctorResolverFailures(t *testing.T) {
	for _, kind := range []string{"none", "lookup", "rcode", "empty", "private", "success"} {
		t.Run(kind, func(t *testing.T) {
			var levels []string
			calls := 0
			doctorDNS(context.Background(), "fixture", nil, func(a netip.Addr) bool { return a == netip.MustParseAddr("1.1.1.1") }, func([]string) ([]string, error) {
				if kind == "none" {
					return nil, errors.New("unavailable")
				}
				return []string{"127.0.0.1"}, nil
			}, func(_ context.Context, raw []byte) ([]byte, error) {
				calls++
				if kind == "lookup" {
					return nil, errors.New("unavailable")
				}
				var q dns.Msg
				if err := q.Unpack(raw); err != nil {
					return nil, err
				}
				m := new(dns.Msg)
				m.SetReply(&q)
				if kind == "rcode" {
					m.Rcode = dns.RcodeServerFailure
				} else if kind != "empty" {
					ip := net.IPv4(1, 1, 1, 1)
					if kind == "private" {
						ip = net.IPv4(127, 0, 0, 1)
					}
					m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: ip}}
				}
				return m.Pack()
			}, func(level, _, _ string) { levels = append(levels, level) })
			if kind == "none" {
				if calls != 0 || len(levels) != 1 || levels[0] != "FAIL" {
					t.Fatal("missing resolver did not fail")
				}
				return
			}
			if calls != 1 || len(levels) != 2 || levels[0] != "PASS" {
				t.Fatal("resolver check changed")
			}
			want := "WARN"
			if kind == "success" {
				want = "PASS"
			}
			if levels[1] != want {
				t.Fatal("lookup must warn on transport, RCODE, empty or denied answers")
			}
		})
	}
}
