package config

import (
	"errors"
	"net/netip"
	"slices"
	"time"
)

// VZNetwork bounds each private VM link; zero values select the defaults.
type VZNetwork struct {
	DNSServers     []string `toml:"dns_servers"`
	MemoryMB       int      `toml:"memory_mb"`
	MaxFlows       int      `toml:"max_flows"`
	TCPIdleTimeout Duration `toml:"tcp_idle_timeout"`
	UDPIdleTimeout Duration `toml:"udp_idle_timeout"`
	MTU            int      `toml:"mtu"`
}

func (n VZNetwork) WithDefaults() VZNetwork {
	if n.MemoryMB == 0 {
		n.MemoryMB = 1024
	}
	if n.MaxFlows == 0 {
		n.MaxFlows = 4096
	}
	if n.TCPIdleTimeout.Duration == 0 {
		n.TCPIdleTimeout.Duration = 24 * time.Hour
	}
	if n.UDPIdleTimeout.Duration == 0 {
		n.UDPIdleTimeout.Duration = 60 * time.Second
	}
	if n.MTU == 0 {
		n.MTU = 16384
	}
	return n
}
func (n VZNetwork) Validate() error {
	n = n.WithDefaults()
	if n.MemoryMB < 1 || n.MemoryMB > 65536 || n.MaxFlows < 1 || n.MaxFlows > 65536 || n.MTU < 1500 || n.MTU > 65535 || n.TCPIdleTimeout.Duration < time.Second || n.TCPIdleTimeout.Duration > 7*24*time.Hour || n.UDPIdleTimeout.Duration < time.Second || n.UDPIdleTimeout.Duration > 24*time.Hour || len(n.DNSServers) > 8 {
		return errors.New("vz.network requires memory_mb 1..65536, max_flows 1..65536, mtu 1500..65535, tcp_idle_timeout 1s..168h, udp_idle_timeout 1s..24h, and at most 8 DNS servers")
	}
	for _, server := range n.DNSServers {
		a, err := netip.ParseAddr(server)
		if err != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a.String() != server {
			return errors.New("vz.network.dns_servers must contain IPv4 unicast literals")
		}
	}
	return nil
}

// DNSConcurrency reserves bounded resolver progress independently of payloads.
func (n VZNetwork) DNSConcurrency() int { return min(256, max(32, n.WithDefaults().MaxFlows/16)) }

func sameDNSServers(a, b []string) bool {
	a = slices.Clone(a)
	b = slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// TCPBufferLimit bounds each direction of the local gVisor TCP leg. The
// budget is a sizing target; the minimum clamp and reserved flows add overhead.
func (n VZNetwork) TCPBufferLimit() int {
	n = n.WithDefaults()
	return min(4<<20, max(128<<10, n.MemoryMB*(1<<20)/(2*n.MaxFlows)))
}
