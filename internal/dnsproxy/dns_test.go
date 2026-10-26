package dnsproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func query(t testing.TB, typ uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("example.invalid.", typ)
	m.Id = 7
	return m
}
func pack(t testing.TB, m *dns.Msg) []byte {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func record(t testing.TB, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
func allow(a netip.Addr) bool { return a == netip.MustParseAddr("1.1.1.1") }

func TestQueryEnvelope(t *testing.T) {
	for _, kind := range []string{"valid", "response", "opcode", "multi", "class", "answer", "authority", "additional", "two-opt", "transfer", "ixfr", "trailing", "edns-version", "sig", "tsig"} {
		t.Run(kind, func(t *testing.T) {
			q := query(t, dns.TypeA)
			switch kind {
			case "response":
				q.Response = true
			case "opcode":
				q.Opcode = dns.OpcodeUpdate
			case "multi":
				q.Question = append(q.Question, q.Question[0])
			case "class":
				q.Question[0].Qclass = dns.ClassCHAOS
			case "answer":
				q.Answer = []dns.RR{record(t, "example.invalid. 30 IN A 1.1.1.1")}
			case "authority":
				q.Ns = []dns.RR{record(t, "example.invalid. 30 IN NS ns.example.invalid.")}
			case "additional":
				q.Extra = []dns.RR{record(t, "example.invalid. 30 IN A 1.1.1.1")}
			case "two-opt":
				q.SetEdns0(4096, true)
				q.SetEdns0(4096, true)
			case "transfer":
				q.Question[0].Qtype = dns.TypeAXFR
			case "ixfr":
				q.Question[0].Qtype = dns.TypeIXFR
			case "edns-version":
				q.SetEdns0(4096, true)
				q.IsEdns0().SetVersion(1)
			case "sig":
				q.Extra = []dns.RR{&dns.SIG{RRSIG: dns.RRSIG{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY}}}}
			case "tsig":
				q.Extra = []dns.RR{&dns.TSIG{Hdr: dns.RR_Header{Name: "key.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY}, Algorithm: "hmac-sha256."}}
			}
			raw := pack(t, q)
			if kind == "trailing" {
				raw = append(raw, 0)
			}
			_, _, err := Query(raw)
			if (err == nil) != (kind == "valid") {
				t.Fatal("envelope admission differs")
			}
		})
	}
	q := query(t, dns.TypeTXT)
	q.SetEdns0(65535, true)
	q.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "aabbccdd"}, &dns.EDNS0_LOCAL{Code: 65000, Data: []byte("opaque")}}
	m, raw, err := Query(pack(t, q))
	if err != nil || m.IsEdns0().UDPSize() != 4096 || !m.IsEdns0().Do() || len(m.IsEdns0().Option) != 0 || bytes.Contains(raw, []byte("opaque")) {
		t.Fatal("EDNS options not rebuilt")
	}
}

func TestFilteringSectionsHintsAndDNSSEC(t *testing.T) {
	for _, kind := range []string{"unchanged", "answer-private", "glue-private", "aaaa", "hints", "mandatory", "rcode-nxdomain", "rcode-servfail", "rcode-refused", "unknown", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			q := query(t, dns.TypeMX)
			m := new(dns.Msg)
			m.SetReply(q)
			m.AuthenticatedData = true
			m.Answer = []dns.RR{record(t, "example.invalid. 123 IN CNAME target.example.invalid."), record(t, "target.example.invalid. 456 IN A 1.1.1.1")}
			modified := false
			switch kind {
			case "answer-private":
				m.Answer = append(m.Answer, record(t, "target.example.invalid. 30 IN A 10.0.0.1"))
				modified = true
			case "glue-private":
				m.Ns = []dns.RR{record(t, "example.invalid. 30 IN A 10.0.0.1")}
				m.Extra = []dns.RR{record(t, "target.example.invalid. 30 IN A 127.0.0.1")}
				modified = true
			case "aaaa":
				m.Answer = append(m.Answer, record(t, "example.invalid. 30 IN AAAA ::1"))
				modified = true
			case "hints":
				m.Answer = append(m.Answer, record(t, "example.invalid. 30 IN HTTPS 1 . alpn=h2 ipv4hint=10.0.0.1 ipv6hint=::1"))
				modified = true
			case "mandatory":
				m.Answer = append(m.Answer, record(t, "example.invalid. 30 IN SVCB 1 . mandatory=ipv4hint ipv4hint=1.1.1.1"))
				modified = true
			case "rcode-nxdomain":
				m.Rcode = dns.RcodeNameError
			case "rcode-servfail":
				m.Rcode = dns.RcodeServerFailure
			case "rcode-refused":
				m.Rcode = dns.RcodeRefused
			case "unknown":
				m.Answer = append(m.Answer, record(t, "example.invalid. 30 IN TYPE65400 \\# 4 c0000201"))
			case "legacy":
				m.Compress = true
				m.Answer = append(m.Answer, record(t, "example.invalid. 30 IN MB mailbox.example.invalid."), record(t, "example.invalid. 30 IN AAAA ::1"))
				modified = true
			}
			if kind == "aaaa" {
				m.Answer = append(m.Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.invalid.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}, TypeCovered: dns.TypeAAAA, SignerName: "example.invalid."})
			}
			raw := pack(t, m)
			filtered, denied, err := Filter(raw, q, allow)
			if err != nil {
				t.Fatal(err)
			}
			var result dns.Msg
			if result.Unpack(filtered) != nil {
				t.Fatal("bad filtered response")
			}
			if !modified && !bytes.Equal(raw, filtered) {
				t.Fatal("unchanged response repacked")
			}
			if modified && result.AuthenticatedData {
				t.Fatal("modified DNSSEC response retained AD")
			}
			if kind == "answer-private" {
				if !denied || result.Rcode != dns.RcodeNameError || len(result.Answer) != 0 {
					t.Fatal("denied answer not NXDOMAIN")
				}
				return
			}
			if result.Rcode != m.Rcode {
				t.Fatal("RCODE changed")
			}
			for _, section := range [][]dns.RR{result.Answer, result.Ns, result.Extra} {
				for _, rr := range section {
					switch v := rr.(type) {
					case *dns.A:
						if !allow(netip.MustParseAddr(v.A.String())) {
							t.Fatal("private glue retained")
						}
					case *dns.AAAA, *dns.RRSIG:
						t.Fatal("IPv6 record/signature retained")
					case *dns.SVCB:
						for _, p := range v.Value {
							if p.Key() == dns.SVCB_IPV4HINT || p.Key() == dns.SVCB_IPV6HINT {
								t.Fatal("hint retained")
							}
						}
					case *dns.HTTPS:
						for _, p := range v.Value {
							if p.Key() == dns.SVCB_IPV4HINT || p.Key() == dns.SVCB_IPV6HINT {
								t.Fatal("hint retained")
							}
						}
					}
				}
			}
			if len(result.Answer) < 2 || result.Answer[0].Header().Ttl != 123 || result.Answer[1].Header().Ttl != 456 {
				t.Fatal("CNAME chain/TTL lost")
			}
		})
	}
}
func TestUDPTruncationAndLargeTCPResponse(t *testing.T) {
	for _, size := range []uint16{0, 1232, 4096, 65535} {
		q := query(t, dns.TypeTXT)
		if size != 0 {
			q.SetEdns0(size, true)
		}
		q, _, err := Query(pack(t, q))
		if err != nil {
			t.Fatal(err)
		}
		m := new(dns.Msg)
		m.SetReply(q)
		for range 200 {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 20}, Txt: []string{strings.Repeat("a", 200)}})
		}
		m.Ns = []dns.RR{record(t, "example.invalid. 30 IN NS ns.example.invalid.")}
		raw := pack(t, m)
		if len(raw) <= 4096 {
			t.Fatal("fixture too small")
		}
		if _, err := ValidateResponse(raw, q); err != nil {
			t.Fatal(err)
		}
		truncated := UDPResponse(raw, q)
		var result dns.Msg
		if result.Unpack(truncated) != nil || !result.Truncated || len(result.Answer) != 0 || len(result.Ns) != 0 || len(result.Question) != 1 {
			t.Fatal("UDP truncation retained sections")
		}
		if len(result.Extra) > 1 {
			t.Fatal("truncation retained extra records")
		}
	}
}
func TestResolverDiscoveryFailureAndTCPFallback(t *testing.T) {
	if _, err := ParseServers([]byte("nameserver invalid\nnameserver 0.0.0.0\n")); err == nil {
		t.Fatal("invalid resolver usable")
	}
	servers, err := ParseServers([]byte("nameserver 127.0.0.1\nnameserver ::1 # local\n"))
	if err != nil || len(servers) != 2 {
		t.Fatal("IPv4/IPv6 resolvers not discovered")
	}
	q := query(t, dns.TypeTXT)
	calls := 0
	r := Resolver{Discover: func([]string) ([]string, error) { return []string{"127.0.0.1"}, nil }, Exchange: func(_ context.Context, server string, raw []byte, network string) ([]byte, error) {
		calls++
		if server != "127.0.0.1" {
			t.Fatal("child selected destination")
		}
		var request dns.Msg
		_ = request.Unpack(raw)
		m := new(dns.Msg)
		m.SetReply(&request)
		m.Truncated = network == "udp"
		return pack(t, m), nil
	}}
	b, err := r.Resolve(context.Background(), pack(t, q))
	if err != nil || calls != 2 {
		t.Fatal("no TCP fallback")
	}
	if _, err := ValidateResponse(b, q); err != nil {
		t.Fatal("response ID/question not restored")
	}
	r.Discover = func([]string) ([]string, error) { return nil, errors.New("fixture unavailable") }
	if _, err := r.Resolve(context.Background(), pack(t, q)); err == nil || calls != 2 {
		t.Fatal("no resolver did not fail closed")
	}
}
func TestResponseIdentity(t *testing.T) {
	q := query(t, dns.TypeA)
	m := new(dns.Msg)
	m.SetReply(q)
	m.Id++
	if _, err := ValidateResponse(pack(t, m), q); err == nil {
		t.Fatal("wrong ID accepted")
	}
	m.SetReply(q)
	m.Question[0].Qtype = dns.TypeTXT
	if _, err := ValidateResponse(pack(t, m), q); err == nil {
		t.Fatal("wrong question accepted")
	}
}

func TestTXTMetadataPasses(t *testing.T) {
	q := query(t, dns.TypeTXT)
	m := new(dns.Msg)
	m.SetReply(q)
	m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{net.IPv4(10, 0, 0, 1).String()}}}
	raw := pack(t, m)
	out, _, err := Filter(raw, q, allow)
	if err != nil || !bytes.Equal(raw, out) {
		t.Fatal("opaque metadata changed")
	}
}

func TestResolverRealUDPTruncationAndLargeTCP(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	errorsOut := make(chan error, 2)
	go func() {
		buf := make([]byte, MaxQuery)
		n, peer, err := udp.ReadFrom(buf)
		if err != nil {
			errorsOut <- err
			return
		}
		var q dns.Msg
		if err = q.Unpack(buf[:n]); err != nil {
			errorsOut <- err
			return
		}
		m := new(dns.Msg)
		m.SetReply(&q)
		m.Truncated = true
		m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"partial"}}}
		raw, err := m.Pack()
		if err == nil {
			_, err = udp.WriteTo(raw[:len(raw)-3], peer)
		}
		errorsOut <- err
	}()
	go func() {
		c, err := tcp.Accept()
		if err != nil {
			errorsOut <- err
			return
		}
		defer func() { _ = c.Close() }()
		var h [2]byte
		if _, err = io.ReadFull(c, h[:]); err != nil {
			errorsOut <- err
			return
		}
		raw := make([]byte, int(binary.BigEndian.Uint16(h[:])))
		if _, err = io.ReadFull(c, raw); err != nil {
			errorsOut <- err
			return
		}
		var q dns.Msg
		if err = q.Unpack(raw); err != nil {
			errorsOut <- err
			return
		}
		m := new(dns.Msg)
		m.SetReply(&q)
		for range 200 {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{strings.Repeat("x", 200)}})
		}
		raw, err = m.Pack()
		if err == nil {
			binary.BigEndian.PutUint16(h[:], uint16(len(raw))) //nolint:gosec // Fixed fixture is below 65535 bytes.
			_, err = c.Write(append(h[:], raw...))
		}
		errorsOut <- err
	}()
	r := Resolver{Discover: func([]string) ([]string, error) { return []string{"fixture"}, nil }, Exchange: func(ctx context.Context, _ string, raw []byte, network string) ([]byte, error) {
		return exchangeAddress(ctx, tcp.Addr().String(), raw, network)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q := query(t, dns.TypeTXT)
	raw, err := r.Resolve(ctx, pack(t, q))
	if err != nil || len(raw) <= 4096 {
		t.Fatal("large response did not traverse real TCP fallback", err)
	}
	if _, err := ValidateResponse(raw, q); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := <-errorsOut; err != nil {
			t.Fatal(err)
		}
	}
}

func TestResolverRetriesTemporaryRCodes(t *testing.T) {
	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNameError} {
		var servers []string
		r := Resolver{Discover: func([]string) ([]string, error) { return []string{"first", "second"}, nil }, Exchange: func(_ context.Context, server string, raw []byte, _ string) ([]byte, error) {
			servers = append(servers, server)
			var q dns.Msg
			if err := q.Unpack(raw); err != nil {
				return nil, err
			}
			m := new(dns.Msg)
			m.SetReply(&q)
			if server == "first" {
				m.Rcode = rcode
			}
			return m.Pack()
		}}
		q := query(t, dns.TypeA)
		raw, err := r.Resolve(context.Background(), pack(t, q))
		if err != nil {
			t.Fatal(err)
		}
		var m dns.Msg
		if m.Unpack(raw) != nil {
			t.Fatal("invalid resolver response")
		}
		want := 2
		if rcode == dns.RcodeNameError {
			want = 1
		}
		if len(servers) != want {
			t.Fatal("resolver did not retry temporary RCODE or retried NXDOMAIN")
		}
		if want == 2 && m.Rcode != dns.RcodeSuccess {
			t.Fatal("second resolver answer not used")
		}
	}
	r := Resolver{Discover: func([]string) ([]string, error) { return []string{"first", "second"}, nil }, Exchange: func(_ context.Context, _ string, raw []byte, _ string) ([]byte, error) {
		var q dns.Msg
		_ = q.Unpack(raw)
		m := new(dns.Msg)
		m.SetRcode(&q, dns.RcodeRefused)
		return m.Pack()
	}}
	raw, err := r.Resolve(context.Background(), pack(t, query(t, dns.TypeA)))
	var m dns.Msg
	if err != nil || m.Unpack(raw) != nil || m.Rcode != dns.RcodeRefused {
		t.Fatal("final temporary RCODE was not preserved")
	}
}
func TestEDNSBadVersionAndSynthesizedOPT(t *testing.T) {
	q := query(t, dns.TypeAAAA)
	q.SetEdns0(1232, true)
	q.IsEdns0().SetVersion(1)
	normalized, _, err := Query(pack(t, q))
	if !errors.Is(err, BadVersion) {
		t.Fatal("version error not distinguished")
	}
	response := Failure(normalized, dns.RcodeBadVers)
	var m dns.Msg
	if m.Unpack(response) != nil || m.Rcode != dns.RcodeBadVers || m.IsEdns0() == nil || m.IsEdns0().Version() != 0 || m.IsEdns0().UDPSize() != 1232 {
		t.Fatal("BADVERS response lacks negotiated OPT")
	}
	normalized.IsEdns0().SetVersion(0)
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeServerFailure, dns.RcodeNameError} {
		raw := Failure(normalized, rcode)
		if m.Unpack(raw) != nil || m.Rcode != rcode || m.IsEdns0() == nil || !m.IsEdns0().Do() {
			t.Fatal("synthesized response omitted OPT")
		}
	}
	called := false
	r := Resolver{Discover: func([]string) ([]string, error) { called = true; return nil, errors.New("must not discover") }}
	if _, err := r.Resolve(context.Background(), pack(t, q)); err != nil || called {
		t.Fatal("BADVERS reached upstream")
	}
}
