package macnetwork

import (
	"errors"
	"net"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Non-default routes include routed networks, point-to-point peers and public links which
// Interface.Addrs alone cannot describe. Default prefixes and ephemeral cloned routes
// are excluded: treating an Internet default as LAN would deny every download.
func connectedRoutes() ([]netip.Prefix, error) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	return connectedPrefixes(messages)
}

func connectedPrefixes(messages []route.Message) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, message := range messages {
		r, ok := message.(*route.RouteMessage)
		if !ok || r.Flags&unix.RTF_UP == 0 || r.Flags&(unix.RTF_WASCLONED|unix.RTF_DYNAMIC) != 0 {
			continue
		}
		// Err describes a routing-socket request reply. This is a sysctl RIB
		// snapshot, whose success is established by FetchRIB and ParseRIB.
		addresses := r.Addrs
		// Even a default route identifies a local next hop. Deny its address
		// independently of the default destination, including /32 host links.
		if r.Flags&unix.RTF_GATEWAY != 0 && len(addresses) > unix.RTAX_GATEWAY {
			if gateway, ok := addresses[unix.RTAX_GATEWAY].(*route.Inet4Addr); ok {
				prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(gateway.IP), 32))
			}
		}
		if len(addresses) <= unix.RTAX_DST {
			return nil, errors.New("connected route destination unavailable")
		}
		dst, ok := addresses[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		bits := 32
		if r.Flags&unix.RTF_HOST == 0 {
			if len(addresses) <= unix.RTAX_NETMASK {
				return nil, errors.New("connected route mask unavailable")
			}
			mask, ok := addresses[unix.RTAX_NETMASK].(*route.Inet4Addr)
			if !ok {
				return nil, errors.New("connected route mask unavailable")
			}
			ones, total := net.IPMask(mask.IP[:]).Size()
			if total != 32 {
				return nil, errors.New("invalid connected route mask")
			}
			bits = ones
		}
		if bits == 0 {
			continue
		}
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(dst.IP), bits).Masked())
	}
	return prefixes, nil
}
