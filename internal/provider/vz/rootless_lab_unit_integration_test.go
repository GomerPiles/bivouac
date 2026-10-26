//go:build integration && darwin

package vz

import (
	"encoding/json"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/rootnet"
	"github.com/GomerPiles/bivouac/internal/vm"
)

func TestRootlessLabUnitSettings(t *testing.T) {
	defaults, err := rootlessLabSettings(func(string) string { return "" })
	if err != nil || defaults.network.MTU != 16384 || defaults.network.MemoryMB != 1024 || defaults.network.MaxFlows != 4096 || defaults.cacheMax != 256 {
		t.Fatal("lab production defaults differ", err)
	}
	values := map[string]string{"BIVOUAC_LAB_MTU": "9000", "BIVOUAC_LAB_MEMORY_MB": "2048", "BIVOUAC_LAB_MAX_FLOWS": "128", "BIVOUAC_LAB_CACHE_MAX_CONNECTIONS": "64", "BIVOUAC_LAB_CACHE_CONCURRENCY": "64", "BIVOUAC_LAB_CACHE_FIXTURE": "fixture", "BIVOUAC_LAB_DNS_SERVERS": "127.0.0.1, 10.0.0.1", "BIVOUAC_LAB_TCP_IDLE_TIMEOUT": "1h", "BIVOUAC_LAB_UDP_IDLE_TIMEOUT": "30s"}
	settings, err := rootlessLabSettings(func(k string) string { return values[k] })
	if err != nil {
		t.Fatal(err)
	}
	rt := &local{store: vm.Store("/tmp/bivouac-lab-unit")}
	args, err := rt.helperArgs("bivouac-macos-lab-unit", Launch{RootlessNetwork: true, Input: true, Network: settings.network, CacheMaxConnections: settings.cacheMax})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := vm.ParseArgs(args[2:])
	if err != nil || !reflect.DeepEqual(parsed.Network, settings.network) || parsed.CacheMaxConnections != 64 || !parsed.RootlessNetwork {
		t.Fatal("lab helper settings lost", err)
	}
	for _, bad := range []map[string]string{
		{"BIVOUAC_LAB_MTU": "1499"}, {"BIVOUAC_LAB_MTU": "65536"}, {"BIVOUAC_LAB_MAX_FLOWS": "0"}, {"BIVOUAC_LAB_MAX_FLOWS": "65537"},
		{"BIVOUAC_LAB_MEMORY_MB": "-1"}, {"BIVOUAC_LAB_MTU": "bad"}, {"BIVOUAC_LAB_DNS_SERVERS": "dns.invalid"}, {"BIVOUAC_LAB_DNS_SERVERS": "1.1.1.1,"},
		{"BIVOUAC_LAB_CACHE_MAX_CONNECTIONS": "65537"}, {"BIVOUAC_LAB_CACHE_CONCURRENCY": "257", "BIVOUAC_LAB_CACHE_FIXTURE": "fixture"},
		{"BIVOUAC_LAB_CACHE_CONCURRENCY": "1"}, {"BIVOUAC_LAB_TCP_IDLE_TIMEOUT": "0s"}, {"BIVOUAC_LAB_UDP_IDLE_TIMEOUT": "25h"},
		{"BIVOUAC_LAB_DNS_PROBES": "1", "BIVOUAC_LAB_DNS_SERVERS": "1.1.1.1"}, {"BIVOUAC_LAB_LIMIT_PROBES": "1", "BIVOUAC_LAB_MAX_FLOWS": "513"},
	} {
		if _, err := rootlessLabSettings(func(k string) string { return bad[k] }); err == nil {
			t.Fatalf("invalid lab settings accepted: %v", bad)
		}
	}
	for _, mtu := range []string{"1500", "9000", "16384", "65535"} {
		if _, err := rootlessLabSettings(func(k string) string {
			if k == "BIVOUAC_LAB_MTU" {
				return mtu
			}
			return ""
		}); err != nil {
			t.Fatal("MTU sweep value rejected", err)
		}
	}
}

func TestRootlessLabUnitParsers(t *testing.T) {
	mtu, err := labInterfaceMTU("en0: flags=8863<UP> mtu 9000\n\tinet 192.0.2.2")
	if err != nil || mtu != 9000 {
		t.Fatal("ifconfig MTU parse failed")
	}
	if _, err := labInterfaceMTU("en0: mtu invalid"); err == nil {
		t.Fatal("invalid MTU accepted")
	}
	for _, value := range []string{"9000", "0x2328"} {
		mtu, ok := labDHCPMTU(" interface_mtu (uint16): " + value + "\nrouter (ip_mult): {192.0.2.1}")
		if !ok || mtu != 9000 {
			t.Fatal("DHCP MTU parse failed")
		}
	}
	if _, ok := labDHCPMTU("router (ip_mult): {192.0.2.1}"); ok {
		t.Fatal("absent DHCP MTU reported")
	}
	cases := labDNSCases()
	valid := []string{
		";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nexample.com. 30 IN A 93.184.215.14\n",
		";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n",
		";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nexample.com. 30 IN TXT \"fixed fixture\"\n",
		";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n",
	}
	for i, output := range valid {
		if !labDigResult(output, cases[i]) {
			t.Fatal("valid DNS result rejected")
		}
		if labDigResult(strings.ReplaceAll(output, "status:", "missing:"), cases[i]) {
			t.Fatal("missing DNS status accepted")
		}
	}
	if labDigResult(valid[1]+"ipv4only.arpa. 30 IN AAAA ::1\n", cases[1]) {
		t.Fatal("nonempty AAAA result accepted")
	}
	if labDigResult(valid[1], cases[0]) {
		t.Fatal("empty A result accepted")
	}
	data := []byte("untrusted text\n" + `{"time":"2026-01-01T00:00:00Z","counters":{"frames":1,"queue_dropped":2}}` + "\n" + `{"time":"2026-01-01T00:01:00Z","counters":{"frames":9,"tcp_retransmits":3}}` + "\n" + `{"time":"2026-01-01T00:02:00Z","other":7}` + "\n{\"time\":")
	r, ok := readLabCounters(data)
	if !ok || r.Counters.Frames != 9 || r.Counters.TCPRetransmits != 3 || r.Time.Minute() != 1 {
		t.Fatal("counter parser accepted partial/noncounter report")
	}
	if _, ok := readLabCounters([]byte("arbitrary helper text")); ok {
		t.Fatal("missing counters accepted")
	}
}

// net.Pipe verifies byte counts and the upload acknowledgement without any
// host listener, public socket, VM or guest agent. Only the live lab proves VZ.
func TestRootlessLabUnitRawTransfer(t *testing.T) {
	for _, mode := range []string{"download", "upload", "pulse"} {
		t.Run(mode, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			done := make(chan error, 1)
			go func() { done <- serveLabRaw(server) }()
			result, err := labRawTransfer(client, mode)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if mode != "pulse" && (result.Bytes != labTCPBytes || result.Seconds <= 0) {
				t.Fatal("raw bytes incomplete")
			}
		})
	}
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = server.Close() }()
		var command [1]byte
		_, _ = io.ReadFull(server, command[:])
		_, _ = io.CopyN(io.Discard, server, labTCPBytes)
	}()
	if _, err := labRawTransfer(client, "upload"); err == nil {
		t.Fatal("unacknowledged upload accepted")
	}
	<-done
}

func TestRootlessLabUnitAlive(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	if labAlive([]net.Conn{client}) != 1 {
		t.Fatal("held connection not counted")
	}
	_ = server.Close()
	if labAlive([]net.Conn{client}) != 0 {
		t.Fatal("closed connection counted as held")
	}
}

func TestRootlessLabUnitFixtureRejectsInput(t *testing.T) {
	for _, req := range []labFixtureRequest{{Mode: "invalid"}, {Mode: "limits", Flows: 0}, {Mode: "limits", Flows: 517}} {
		b, _ := json.Marshal(req)
		if runLabFixture(strings.NewReader(string(b)), io.Discard) != 2 {
			t.Fatal("unbounded or unknown fixture operation accepted")
		}
	}
}

func TestRootlessLabUnitGaugeBasedLimitPlan(t *testing.T) {
	settings, err := rootlessLabSettings(func(k string) string {
		if k == "BIVOUAC_LAB_LIMIT_PROBES" {
			return "1"
		}
		return ""
	})
	if err != nil || settings.network.MaxFlows != 256 {
		t.Fatal("limit default does not reserve background headroom", err)
	}
	for _, test := range []struct {
		tcp, udp, cache uint64
		ceiling, want   int
		valid           bool
	}{
		{60, 3, 1, 256, 260, true}, {0, 0, 0, 256, 260, true}, {7, 0, 1, 16, 20, true},
		{9, 0, 0, 16, 0, false}, {17, 0, 0, 16, 0, false}, {8, 8, 1, 16, 0, false},
		{0, 0, 0, 513, 0, false},
	} {
		snapshot := rootnet.Snapshot{ActivePublicTCP: test.tcp, ActiveUDP: test.udp, ActiveCache: test.cache}
		attempts, err := labLimitAttempts(snapshot, test.ceiling)
		if (err == nil) != test.valid || (err == nil && attempts != test.want) {
			t.Fatal("incorrect gauge-derived attempt plan")
		}
	}
	r, ok := readLabCounters([]byte(`{"time":"2026-01-01T00:00:00Z","counters":{"active_public_tcp":60,"active_udp":3,"active_cache":1}}`))
	if !ok || !r.gaugesPresent || r.Counters.ActivePublicTCP != 60 {
		t.Fatal("active gauges were not parsed")
	}
	old, ok := readLabCounters([]byte(`{"time":"2026-01-01T00:00:00Z","counters":{"frames":1}}`))
	if !ok || old.gaugesPresent {
		t.Fatal("missing active gauges were treated as observed zero")
	}
}
