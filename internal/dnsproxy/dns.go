// Package dnsproxy implements the fixed-function DNS capability. Only the owner
// selects resolver destinations; both sides validate and rebuild query envelopes.
package dnsproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const MaxQuery = 4096
const MaxResponse = 65535

// BadVersion identifies an otherwise valid envelope requiring a local BADVERS.
type QueryError uint8

const BadVersion QueryError = 1

func (QueryError) Error() string { return "unsupported EDNS version" }

// Query removes every EDNS option, retaining only bounded size and DO. It
// rejects trailing bytes as well as non-query, transfer and signed envelopes.
func Query(raw []byte) (*dns.Msg, []byte, error) {
	fail := func() (*dns.Msg, []byte, error) { return nil, nil, errors.New("invalid DNS query") }
	if len(raw) < 12 || len(raw) > MaxQuery {
		return fail()
	}
	var m dns.Msg
	if m.Unpack(raw) != nil || m.Response || m.Opcode != dns.OpcodeQuery || m.Rcode != dns.RcodeSuccess || len(m.Question) != 1 || len(m.Answer) != 0 || len(m.Ns) != 0 || len(m.Extra) > 1 {
		return fail()
	}
	q := m.Question[0]
	if q.Qclass != dns.ClassINET || q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		return fail()
	}
	_, offset, err := dns.UnpackDomainName(raw, 12)
	if err != nil || offset+4 > len(raw) {
		return fail()
	}
	offset += 4
	badVersion := false
	if len(m.Extra) == 1 {
		opt, ok := m.Extra[0].(*dns.OPT)
		if !ok || opt.Hdr.Name != "." {
			return fail()
		}
		badVersion = opt.Version() != 0
		_, pos, err := dns.UnpackDomainName(raw, offset)
		if err != nil || pos+10 > len(raw) {
			return fail()
		}
		offset = pos + 10 + int(binary.BigEndian.Uint16(raw[pos+8:pos+10]))
		size := min(4096, max(512, opt.UDPSize()))
		do := opt.Do()
		m.Extra = nil
		m.SetEdns0(size, do)
	}
	if offset != len(raw) {
		return fail()
	}
	m.AuthenticatedData = false
	m.CheckingDisabled = false
	m.Truncated = false
	m.Authoritative = false
	m.RecursionAvailable = false
	m.Zero = false
	packed, err := m.Pack()
	if err != nil {
		return fail()
	}
	if badVersion {
		return &m, nil, BadVersion
	}
	return &m, packed, nil
}

func ValidateResponse(raw []byte, q *dns.Msg) (*dns.Msg, error) {
	var m dns.Msg
	if len(raw) > MaxResponse || m.Unpack(raw) != nil || !m.Response || m.Opcode != dns.OpcodeQuery || m.Id != q.Id || len(m.Question) != 1 || !strings.EqualFold(m.Question[0].Name, q.Question[0].Name) || m.Question[0].Qtype != q.Question[0].Qtype || m.Question[0].Qclass != q.Question[0].Qclass {
		return nil, errors.New("invalid DNS response")
	}
	return &m, nil
}
func Failure(q *dns.Msg, rcode int) []byte {
	m := new(dns.Msg)
	m.SetRcode(q, rcode)
	m.RecursionAvailable = true
	if opt := q.IsEdns0(); opt != nil {
		m.SetEdns0(opt.UDPSize(), opt.Do())
	}
	b, _ := m.Pack()
	return b
}
func UDPResponse(raw []byte, q *dns.Msg) []byte {
	size := 512
	if opt := q.IsEdns0(); opt != nil {
		size = int(opt.UDPSize())
	}
	if len(raw) <= size {
		return raw
	}
	m, err := ValidateResponse(raw, q)
	if err != nil {
		return nil
	}
	m.Answer = nil
	m.Ns = nil
	m.Extra = nil
	m.Truncated = true
	m.AuthenticatedData = false
	if opt := q.IsEdns0(); opt != nil {
		m.SetEdns0(opt.UDPSize(), opt.Do())
	}
	b, _ := m.Pack()
	return b
}

// Servers rereads primary resolvers on each operation. Scoped macOS resolvers
// and search domains are deliberately outside this protocol-forwarding promise.
func Servers(overrides []string) ([]string, error) {
	if len(overrides) != 0 {
		out := make([]string, 0, len(overrides))
		for _, s := range overrides {
			a, e := netip.ParseAddr(s)
			if e != nil || a.IsUnspecified() || a.IsMulticast() {
				return nil, errors.New("invalid resolver")
			}
			out = append(out, a.String())
		}
		return out, nil
	}
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, errors.New("resolver configuration unavailable")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 {
		return nil, errors.New("resolver configuration unavailable")
	}
	return ParseServers(b)
}
func ParseServers(data []byte) ([]string, error) {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		a, e := netip.ParseAddr(fields[1])
		if e == nil && !a.IsUnspecified() && !a.IsMulticast() {
			out = append(out, a.String())
			if len(out) == 8 {
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no usable primary resolver")
	}
	return out, nil
}

type Resolver struct {
	Overrides []string
	// Discovery and Exchange are owner-selected fixture seams, never child input.
	Discover func([]string) ([]string, error)
	Exchange func(context.Context, string, []byte, string) ([]byte, error)
}

func (r Resolver) Resolve(ctx context.Context, input []byte) ([]byte, error) {
	q, request, err := Query(input)
	if errors.Is(err, BadVersion) {
		return Failure(q, dns.RcodeBadVers), nil
	}
	if err != nil {
		return nil, err
	}
	discover := r.Discover
	if discover == nil {
		discover = Servers
	}
	servers, err := discover(r.Overrides)
	if err != nil {
		return nil, err
	}
	exchange := r.Exchange
	if exchange == nil {
		exchange = Exchange
	}
	originalID := q.Id
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, errors.New("DNS randomness unavailable")
	}
	q.Id = binary.BigEndian.Uint16(id[:])
	binary.BigEndian.PutUint16(request, q.Id)
	var temporary []byte
	for _, server := range servers {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		response, e := exchange(attempt, server, request, "udp")
		if e == nil {
			_, e = ValidateResponse(response, q)
			// A truncated UDP body may end inside an RR. Validate its header and
			// question before retrying over TCP instead of requiring the cut RR.
			if truncatedQuestion(response, q) {
				response, e = exchange(attempt, server, request, "tcp")
				if e == nil {
					_, e = ValidateResponse(response, q)
				}
			}
		}
		cancel()
		if e == nil {
			m, _ := ValidateResponse(response, q)
			binary.BigEndian.PutUint16(response, originalID)
			if m.Rcode == dns.RcodeServerFailure || m.Rcode == dns.RcodeRefused {
				temporary = response
				continue
			}
			return response, nil
		}
	}
	if temporary != nil {
		return temporary, nil
	}
	return nil, errors.New("DNS resolvers unavailable")
}

func Exchange(ctx context.Context, server string, request []byte, network string) ([]byte, error) {
	return exchangeAddress(ctx, net.JoinHostPort(server, "53"), request, network)
}
func exchangeAddress(ctx context.Context, address string, request []byte, network string) ([]byte, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, errors.New("DNS transport unavailable")
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = c.SetDeadline(deadline)
	if network == "tcp" {
		var h [2]byte
		binary.BigEndian.PutUint16(h[:], uint16(len(request))) //nolint:gosec // Query is bounded to 4096.
		if _, err = io.Copy(c, bytes.NewReader(append(h[:], request...))); err != nil {
			return nil, err
		}
		if _, err = io.ReadFull(c, h[:]); err != nil {
			return nil, err
		}
		b := make([]byte, int(binary.BigEndian.Uint16(h[:])))
		_, err = io.ReadFull(c, b)
		return b, err
	}
	if _, err = c.Write(request); err != nil {
		return nil, err
	}
	b := make([]byte, MaxResponse+1)
	n, err := c.Read(b)
	if n > MaxResponse {
		return nil, errors.New("oversize DNS response")
	}
	return b[:n], err
}

func truncatedQuestion(raw []byte, q *dns.Msg) bool {
	if len(raw) < 12 || binary.BigEndian.Uint16(raw) != q.Id || binary.BigEndian.Uint16(raw[2:4])&0xfa00 != 0x8200 || binary.BigEndian.Uint16(raw[4:6]) != 1 {
		return false
	}
	name, pos, err := dns.UnpackDomainName(raw, 12)
	return err == nil && pos+4 <= len(raw) && strings.EqualFold(name, q.Question[0].Name) && binary.BigEndian.Uint16(raw[pos:pos+2]) == q.Question[0].Qtype && binary.BigEndian.Uint16(raw[pos+2:pos+4]) == q.Question[0].Qclass
}
