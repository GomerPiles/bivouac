package config

import (
	"testing"
	"time"
)

func TestVZNetworkDefaultsAndRanges(t *testing.T) {
	n := (VZNetwork{}).WithDefaults()
	if n.MaxFlows != 4096 || n.MTU != 16384 || n.TCPIdleTimeout.Duration != 24*time.Hour || n.UDPIdleTimeout.Duration != 60*time.Second || n.DNSConcurrency() != 256 {
		t.Fatal("network defaults changed")
	}
	for _, bad := range []VZNetwork{{MaxFlows: -1}, {MaxFlows: 65537}, {MTU: 1499}, {MTU: 65536}, {TCPIdleTimeout: Duration{-time.Second}}, {UDPIdleTimeout: Duration{25 * time.Hour}}, {DNSServers: []string{"dns.invalid"}}, {DNSServers: []string{"::1"}}, {DNSServers: []string{"0.0.0.0"}}} {
		if bad.Validate() == nil {
			t.Fatal("invalid network configuration accepted")
		}
	}
	if (VZNetwork{DNSServers: []string{"127.0.0.1", "10.0.0.1"}}).Validate() != nil {
		t.Fatal("operator resolver override subjected to public admission")
	}
	if !sameDNSServers([]string{"1.1.1.1", "8.8.8.8"}, []string{"8.8.8.8", "1.1.1.1"}) || sameDNSServers(nil, []string{"1.1.1.1"}) {
		t.Fatal("inconsistent shared cache overrides")
	}
}

func TestVZProvidersMustAgreeOnDNSOverrides(t *testing.T) {
	c, err := Parse([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	original := c.Providers["macos"]
	second := original
	copyVZ := *original.VZ
	second.VZ = &copyVZ
	second.ScaleSet = "bivouac-second"
	second.VZ.Network.DNSServers = []string{"1.1.1.1"}
	c.Providers["second"] = second
	if c.Validate() == nil {
		t.Fatal("inconsistent overrides accepted")
	}
	original.VZ.Network.DNSServers = []string{"1.1.1.1"}
	if err := c.Validate(); err != nil {
		t.Fatal("matching overrides refused", err)
	}
	c.Cache.MaxConnections = -1
	if c.Validate() == nil {
		t.Fatal("negative endpoint bound accepted")
	}
}

func TestNetworkMemoryBudget(t *testing.T) {
	if (VZNetwork{}).WithDefaults().MemoryMB != 1024 || (VZNetwork{}).TCPBufferLimit() != 128<<10 {
		t.Fatal("default budget not one GiB / 4096 flows")
	}
	for _, mtu := range []int{1500, 9000, 16384, 65535} {
		if (VZNetwork{MTU: mtu}).WithDefaults().MemoryMB != 1024 || (VZNetwork{MTU: mtu}).TCPBufferLimit() != 128<<10 {
			t.Fatal("MTU changed the independent TCP sizing budget")
		}
	}
	for _, n := range []VZNetwork{{MemoryMB: -1}, {MemoryMB: 65537}} {
		if n.Validate() == nil {
			t.Fatal("invalid memory budget accepted")
		}
	}
	if (VZNetwork{MemoryMB: 1, MaxFlows: 65536}).TCPBufferLimit() != 128<<10 || (VZNetwork{MemoryMB: 65536, MaxFlows: 1}).TCPBufferLimit() != 4<<20 {
		t.Fatal("buffer clamps not applied")
	}
}
