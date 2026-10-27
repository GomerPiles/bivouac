package macnetwork

import (
	"context"
	"errors"
	"net"
	"slices"
	"time"

	"github.com/GomerPiles/bivouac/internal/dnsproxy"
	"github.com/miekg/dns"
)

// Resolver uses system name routing unless the operator chose explicit servers.
// Overrides bypass host name sources; admission remains the caller's job.
func Resolver(servers []string) func(context.Context, string) ([]net.IPAddr, error) {
	if len(servers) == 0 {
		return net.DefaultResolver.LookupIPAddr
	}
	return resolverLookup((dnsproxy.Resolver{Overrides: slices.Clone(servers)}).Resolve)
}
func resolverLookup(exchange func(context.Context, []byte) ([]byte, error)) func(context.Context, string) ([]net.IPAddr, error) {
	return func(parent context.Context, name string) ([]net.IPAddr, error) {
		if ip := net.ParseIP(name); ip != nil {
			return []net.IPAddr{{IP: ip}}, nil
		}
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(name), dns.TypeA)
		raw, err := q.Pack()
		if err != nil {
			return nil, errors.New("invalid DNS name")
		}
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		response, err := exchange(ctx, raw)
		if err != nil {
			return nil, errors.New("configured DNS unavailable")
		}
		m, err := dnsproxy.ValidateResponse(response, q)
		if err != nil {
			return nil, err
		}
		if m.Rcode == dns.RcodeNameError {
			return nil, &net.DNSError{IsNotFound: true}
		}
		if m.Rcode != dns.RcodeSuccess {
			return nil, errors.New("configured DNS failed")
		}
		var ips []net.IPAddr
		for _, rr := range m.Answer {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, net.IPAddr{IP: v.A})
			case *dns.AAAA:
				ips = append(ips, net.IPAddr{IP: v.AAAA})
			}
		}
		return ips, nil
	}
}
