package dnsproxy

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

type rrset struct {
	name       string
	typ, class uint16
}

func recordSet(rr dns.RR, typ uint16) rrset {
	h := rr.Header()
	return rrset{strings.ToLower(h.Name), typ, h.Class}
}

// Filter runs only with the child's current admission policy. Unknown RDATA is
// opaque. Unchanged responses retain their exact wire representation; rewritten
// messages use the codec's record-aware name compression and RFC3597 support.
func Filter(raw []byte, q *dns.Msg, allow func(netip.Addr) bool) ([]byte, bool, error) {
	m, err := ValidateResponse(raw, q)
	if err != nil {
		return nil, false, err
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			ip, valid := netip.AddrFromSlice(a.A)
			if !valid || !allow(ip.Unmap()) {
				return Failure(q, dns.RcodeNameError), true, nil
			}
		}
	}
	changed := map[rrset]bool{}
	sections := []*[]dns.RR{&m.Answer, &m.Ns, &m.Extra}
	for _, section := range sections {
		kept := make([]dns.RR, 0, len(*section))
		for _, rr := range *section {
			drop, modify := false, false
			switch v := rr.(type) {
			case *dns.AAAA:
				drop = true
			case *dns.A:
				ip, ok := netip.AddrFromSlice(v.A)
				drop = !ok || !allow(ip.Unmap())
			case *dns.SVCB:
				drop, modify = stripHints(v)
			case *dns.HTTPS:
				drop, modify = stripHints(&v.SVCB)
			}
			if drop || modify {
				changed[recordSet(rr, rr.Header().Rrtype)] = true
			}
			if !drop {
				kept = append(kept, rr)
			}
		}
		*section = kept
	}
	if len(changed) == 0 {
		b := append([]byte(nil), raw...)
		binary.BigEndian.PutUint16(b, q.Id)
		return b, false, nil
	}
	for _, section := range sections {
		kept := (*section)[:0]
		for _, rr := range *section {
			if sig, ok := rr.(*dns.RRSIG); ok && changed[recordSet(sig, sig.TypeCovered)] {
				continue
			}
			kept = append(kept, rr)
		}
		*section = kept
	}
	m.AuthenticatedData = false
	m.Compress = true
	b, err := m.Pack()
	if err != nil || len(b) > MaxResponse {
		return nil, false, errors.New("filtered DNS response unavailable")
	}
	return b, false, nil
}
func stripHints(v *dns.SVCB) (drop, changed bool) {
	for _, p := range v.Value {
		if mandatory, ok := p.(*dns.SVCBMandatory); ok {
			for _, key := range mandatory.Code {
				if key == dns.SVCB_IPV4HINT || key == dns.SVCB_IPV6HINT {
					return true, true
				}
			}
		}
	}
	kept := v.Value[:0]
	for _, p := range v.Value {
		if p.Key() == dns.SVCB_IPV4HINT || p.Key() == dns.SVCB_IPV6HINT {
			changed = true
			continue
		}
		kept = append(kept, p)
	}
	v.Value = kept
	return false, changed
}
