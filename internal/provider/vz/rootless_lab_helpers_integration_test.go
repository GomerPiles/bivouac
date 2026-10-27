//go:build integration && darwin

package vz

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cachelink"
	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/rootnet"
	"golang.org/x/net/dns/dnsmessage"
)

type labSettings struct {
	network           config.VZNetwork
	cacheMax, readers int
}

func rootlessLabSettings(env func(string) string) (labSettings, error) {
	s := labSettings{cacheMax: 256}
	if env("BIVOUAC_LAB_LIMIT_PROBES") == "1" && env("BIVOUAC_LAB_MAX_FLOWS") == "" {
		s.network.MaxFlows = 256
	}
	for _, field := range []struct {
		name string
		dst  *int
	}{
		{"MTU", &s.network.MTU}, {"MEMORY_MB", &s.network.MemoryMB}, {"MAX_FLOWS", &s.network.MaxFlows},
		{"CACHE_MAX_CONNECTIONS", &s.cacheMax}, {"CACHE_CONCURRENCY", &s.readers},
	} {
		if value := env("BIVOUAC_LAB_" + field.name); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 {
				return s, fmt.Errorf("BIVOUAC_LAB_%s requires a positive integer", field.name)
			}
			*field.dst = n
		}
	}
	for _, field := range []struct {
		name string
		dst  *config.Duration
	}{
		{"TCP_IDLE_TIMEOUT", &s.network.TCPIdleTimeout}, {"UDP_IDLE_TIMEOUT", &s.network.UDPIdleTimeout},
	} {
		if value := env("BIVOUAC_LAB_" + field.name); value != "" {
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 {
				return s, fmt.Errorf("BIVOUAC_LAB_%s requires a positive duration", field.name)
			}
			field.dst.Duration = d
		}
	}
	if value := env("BIVOUAC_LAB_DNS_SERVERS"); value != "" {
		s.network.DNSServers = strings.Split(value, ",")
		for i := range s.network.DNSServers {
			s.network.DNSServers[i] = strings.TrimSpace(s.network.DNSServers[i])
		}
	}
	s.network = s.network.WithDefaults()
	// Use production validation, including cache.max_connections, without reading
	// the operator's config or requiring credentials for this credential-free lab.
	c, err := config.Parse([]byte(config.Example))
	if err != nil {
		return s, errors.New("lab validation template invalid")
	}
	c.Providers["macos"].VZ.Network = s.network
	c.Cache.MaxConnections = s.cacheMax
	if err := c.Validate(); err != nil {
		return s, err
	}
	if s.readers > s.cacheMax || s.readers > s.network.MaxFlows {
		return s, errors.New("cache concurrency exceeds cache bound or general flow ceiling")
	}
	if s.readers != 0 && env("BIVOUAC_LAB_PUBLIC_ASSET") == "" && env("BIVOUAC_LAB_CACHE_FIXTURE") == "" {
		return s, errors.New("local warm cache concurrency requires BIVOUAC_LAB_CACHE_FIXTURE")
	}
	if env("BIVOUAC_LAB_DNS_PROBES") == "1" && len(s.network.DNSServers) != 0 {
		return s, errors.New("host DNS probes require dns_servers unset")
	}
	if env("BIVOUAC_LAB_LIMIT_PROBES") == "1" && s.network.MaxFlows > 512 {
		return s, errors.New("limit probes require max_flows 1..512 to bound public connects")
	}
	return s, nil
}

func labInterfaceMTU(output string) (int, error) {
	f := strings.Fields(output)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "mtu" {
			return strconv.Atoi(f[i+1])
		}
	}
	return 0, errors.New("interface MTU missing")
}

func labDHCPMTU(output string) (int, bool) {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.TrimSpace(key) == "interface_mtu (uint16)" {
			n, err := strconv.ParseInt(strings.TrimSpace(value), 0, 32)
			return int(n), err == nil
		}
	}
	return 0, false
}

func checkLabMTU(t *testing.T, ctx context.Context, p *Provider, name string, want int) {
	t.Helper()
	output, err := p.guest(ctx, name, []string{"/sbin/ifconfig", "en0"}, nil, 8192)
	mtu, parseErr := labInterfaceMTU(string(output))
	if err != nil || parseErr != nil {
		t.Fatal("guest primary interface MTU unavailable")
	}
	t.Logf("guest_interface interface=en0 configured_mtu=%d actual_mtu=%d", want, mtu)
	if mtu != want {
		t.Fatal("guest did not adopt configured MTU")
	}
	packet, err := p.guest(ctx, name, []string{"/usr/sbin/ipconfig", "getpacket", "en0"}, nil, 8192)
	dhcpMTU, ok := labDHCPMTU(string(packet))
	t.Logf("guest_dhcp interface=en0 mtu_available=%t mtu=%d", err == nil && ok, dhcpMTU)
	if err == nil && ok && dhcpMTU != want {
		t.Fatal("DHCP MTU differs from configured MTU")
	}
}

// These fixed queries disclose no operator-chosen names. AAAA is deliberately
// suppressed by the IPv4-only service, independently of the upstream RRset.
type labDNSCase struct {
	name, kind, status string
	empty              bool
}

func labDNSCases() []labDNSCase {
	return []labDNSCase{{"example.com", "A", "NOERROR", false}, {"ipv4only.arpa", "AAAA", "NOERROR", true}, {"example.com", "TXT", "NOERROR", false}, {"bivouac-lab-nonexistent.invalid", "A", "NXDOMAIN", true}}
}

func labDigResult(output string, probe labDNSCase) bool {
	statusOK := false
	answers := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "status: "+probe.status+",") {
			statusOK = true
		}
		f := strings.Fields(line)
		if len(f) >= 5 && !strings.HasPrefix(f[0], ";") && f[2] == "IN" {
			answers++
			if f[3] != probe.kind && f[3] != "CNAME" {
				return false
			}
		}
	}
	return statusOK && ((probe.empty && answers == 0) || (!probe.empty && answers > 0))
}

func labDNSTool(t *testing.T, ctx context.Context, p *Provider, name string) string {
	t.Helper()
	// Prove the resolver was supplied by DHCP before explicitly selecting it.
	dns, err := p.guest(ctx, name, []string{"/usr/sbin/ipconfig", "getoption", "en0", "domain_name_server"}, nil, 128)
	if err != nil || strings.TrimSpace(string(dns)) != rootnet.Gateway {
		t.Fatal("DHCP resolver is not the virtual DNS service")
	}
	for _, tool := range []string{"/usr/bin/dig", "/usr/bin/host"} {
		if _, err := p.guest(ctx, name, []string{"/bin/test", "-x", tool}, nil, 1); err == nil {
			return tool
		}
	}
	t.Log("dns_probes=skipped reason=dig_and_host_unavailable dscacheutil_cannot_verify_TXT_or_RCODE")
	return ""
}

func runLabDNS(t *testing.T, parent context.Context, p *Provider, name, tool string, probe labDNSCase) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	args := []string{tool, "@" + rootnet.Gateway, probe.name, probe.kind, "+time=3", "+tries=1", "+noall", "+comments", "+answer"}
	if strings.HasSuffix(tool, "/host") {
		args = []string{tool, "-W", "3", "-R", "1", "-v", "-t", probe.kind, probe.name, rootnet.Gateway}
	}
	output, err := p.guest(ctx, name, args, nil, 8192)
	ok := labDigResult(string(output), probe)
	if strings.HasSuffix(tool, "/host") {
		// host -v renders the same HEADER/status format, with human-readable RRs.
		text := string(output)
		switch probe.kind {
		case "A":
			ok = strings.Contains(text, "has address") && strings.Contains(text, "status: NOERROR,")
		case "TXT":
			ok = strings.Contains(text, "descriptive text") && strings.Contains(text, "status: NOERROR,")
		case "AAAA":
			ok = strings.Contains(text, "status: NOERROR,") && strings.Contains(text, "ANSWER: 0,")
		}
		if probe.status == "NXDOMAIN" {
			ok = strings.Contains(text, "NXDOMAIN")
		}
	}
	// host exits nonzero for valid NODATA/NXDOMAIN; never accept a transport error
	// without the expected parsed status. No raw guest output enters logs.
	if !ok || (err != nil && strings.HasSuffix(tool, "/dig")) {
		t.Fatalf("dns_probe type=%s expected_status=%s expected_empty=%t failed", probe.kind, probe.status, probe.empty)
	}
	t.Logf("dns_probe type=%s status=%s empty=%t passed=true", probe.kind, probe.status, probe.empty)
}

func probeLabDNS(t *testing.T, ctx context.Context, p *Provider, name string) {
	t.Helper()
	if tool := labDNSTool(t, ctx, p, name); tool != "" {
		for _, probe := range labDNSCases() {
			runLabDNS(t, ctx, p, name, tool, probe)
		}
	}
}

const labGuestFixture = "/tmp/bivouac-rootless-lab-fixture"
const labTCPBytes = 256 << 20

type labFixtureRequest struct {
	Mode  string
	Flows int
}
type labFixtureResult struct {
	Bytes                int64
	Seconds              float64
	Open, Refused, Alive int
}

func stageLabFixture(t *testing.T, ctx context.Context, p *Provider, name string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("lab fixture executable unavailable")
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal("lab fixture executable unavailable")
	}
	defer func() { _ = f.Close() }()
	for _, args := range [][]string{{"/bin/rm", "-f", labGuestFixture}, {"/usr/bin/install", "-m", "0700", "/dev/null", labGuestFixture}} {
		if err := labExec(t, ctx, p, name, "fixture_stage", args, nil, io.Discard); err != nil {
			t.Fatal("lab fixture staging failed")
		}
	}
	if err := labExec(t, ctx, p, name, "fixture_upload", []string{"/bin/dd", "of=" + labGuestFixture, "status=none"}, f, io.Discard); err != nil {
		t.Fatal("lab fixture upload failed")
	}
}

func labFixtureArgs() []string {
	return []string{labGuestFixture, "-test.run=^TestRootlessLabGuestFixture$", "--", "rootless-lab-fixture"}
}

func TestRootlessLabGuestFixture(t *testing.T) {
	if os.Args[len(os.Args)-1] != "rootless-lab-fixture" {
		return
	}
	// This subprocess runs only inside the recorded disposable guest; normal
	// unit/integration selection cannot trigger its socket operations.
	os.Exit(runLabFixture(os.Stdin, os.Stdout))
}

func runLabFixture(input io.Reader, output io.Writer) int {
	decoder := json.NewDecoder(input)
	encoder := json.NewEncoder(output)
	var req labFixtureRequest
	if decoder.Decode(&req) != nil {
		return 2
	}
	if req.Mode == "dns-pulse" {
		if err := labDNSPulse(); err != nil {
			labFixtureStage("dns_pulse", err)
			return 3
		}
		if encoder.Encode(labFixtureResult{}) != nil {
			return 3
		}
		return 0
	}
	if req.Mode == "limits" {
		return labHoldFlows(decoder, encoder, req.Flows)
	}
	if req.Mode != "download" && req.Mode != "upload" && req.Mode != "pulse" {
		return 2
	}
	c, err := net.DialTimeout("tcp4", "192.0.2.1:7443", 5*time.Second)
	if err != nil {
		labFixtureStage("raw_dial", err)
		return 3
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	result, err := labRawTransfer(c, req.Mode)
	if err != nil {
		labFixtureStage("raw_transfer", err)
		return 3
	}
	if err := encoder.Encode(result); err != nil {
		labFixtureStage("raw_metrics", err)
		return 3
	}
	return 0
}

func labRawTransfer(c net.Conn, mode string) (labFixtureResult, error) {
	start := time.Now()
	command := map[string]byte{"download": 'd', "upload": 'u', "pulse": 'p'}[mode]
	if _, err := c.Write([]byte{command}); err != nil {
		return labFixtureResult{}, err
	}
	var n int64
	var err error
	switch mode {
	case "download":
		n, err = io.CopyN(io.Discard, c, labTCPBytes)
	case "upload":
		n, err = io.CopyN(c, labZeroReader{}, labTCPBytes)
		if err == nil {
			var ack [1]byte
			_, err = io.ReadFull(c, ack[:])
			if err == nil && ack[0] != 'a' {
				err = io.ErrUnexpectedEOF
			}
		}
	case "pulse":
		var ack [1]byte
		_, err = io.ReadFull(c, ack[:])
	default:
		err = errors.New("invalid raw transfer mode")
	}
	return labFixtureResult{Bytes: n, Seconds: time.Since(start).Seconds()}, err
}

func serveLabRaw(c net.Conn) error {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(65 * time.Second))
	var command [1]byte
	if _, err := io.ReadFull(c, command[:]); err != nil {
		return err
	}
	switch command[0] {
	case 'd':
		_, err := io.CopyN(c, labZeroReader{}, labTCPBytes)
		return err
	case 'u':
		if _, err := io.CopyN(io.Discard, c, labTCPBytes); err != nil {
			return err
		}
		_, err := c.Write([]byte{'a'})
		return err
	case 'p':
		_, err := c.Write([]byte{'a'})
		return err
	default:
		return errors.New("invalid raw command")
	}
}

// The existing cache capability is the sole host endpoint. Guest TCP traverses
// virtio Ethernet, the VZ datagram attachment, netstack and the parent broker.
// Agent VSOCK carries only fixture commands and tiny numeric results.
func measureLabTCP(t *testing.T, parent context.Context, p *Provider, name, logPath string) {
	t.Helper()
	if err := p.runnerIsolation(name); err != nil {
		t.Fatal("raw endpoint ownership unproven")
	}
	listener, err := p.store.ListenCache(name, cachelink.Payload)
	if err != nil {
		t.Fatal("raw endpoint unavailable")
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
	defer func() { _ = listener.Close(); <-done; workers.Wait() }()
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() { _ = serveLabRaw(c) })
		}
	}()
	run := func(mode string) labFixtureResult {
		input, _ := json.Marshal(labFixtureRequest{Mode: mode})
		out := &boundedBuffer{limit: 1024}
		ctx, cancel := context.WithTimeout(parent, 70*time.Second)
		defer cancel()
		err := labExec(t, ctx, p, name, "raw_"+mode, labFixtureArgs(), bytes.NewReader(input), out)
		var result labFixtureResult
		if err != nil || json.Unmarshal(out.data, &result) != nil {
			t.Fatal("local raw fixture failed")
		}
		return result
	}
	fresh := func() labCounterReport {
		after := time.Now()
		return waitLabCounters(t, parent, logPath, func(r labCounterReport) bool { return !r.Time.Before(after) }, func() { run("pulse") })
	}
	before := fresh()
	for _, mode := range []string{"download", "upload"} {
		result := run(mode)
		if result.Bytes != labTCPBytes || result.Seconds <= 0 {
			t.Fatal("raw virtual TCP transfer incomplete")
		}
		after := fresh()
		direction := "host_to_guest"
		if mode == "upload" {
			direction = "guest_to_host"
		}
		t.Logf("local_tcp direction=%s mtu=%d bytes=%d seconds=%.6f mb_per_second=%.2f", direction, p.cfg.Network.MTU, result.Bytes, result.Seconds, float64(result.Bytes)/result.Seconds/1e6)
		logLabCounters(t, mode+"_before", before)
		logLabCounters(t, mode+"_after", after)
		if after.Counters.Frames <= before.Counters.Frames {
			t.Fatal("raw measurement did not advance Ethernet counters")
		}
		before = after
	}
}

type labCounterReport struct {
	gaugesPresent bool
	Time          time.Time         `json:"time"`
	Counters      *rootnet.Snapshot `json:"counters"`
}

func readLabCounters(data []byte) (labCounterReport, bool) {
	var latest labCounterReport
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		var r labCounterReport
		if json.Unmarshal(line, &r) == nil && r.Counters != nil && !r.Time.IsZero() {
			var fields struct {
				Counters map[string]json.RawMessage `json:"counters"`
			}
			if json.Unmarshal(line, &fields) == nil {
				_, tcp := fields.Counters["active_public_tcp"]
				_, udp := fields.Counters["active_udp"]
				_, cache := fields.Counters["active_cache"]
				r.gaugesPresent = tcp && udp && cache
			}
			latest = r
		}
	}
	return latest, latest.Counters != nil
}
func waitLabCounters(t *testing.T, parent context.Context, path string, accept func(labCounterReport) bool, pulse func()) labCounterReport {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 85*time.Second)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("numeric helper log unavailable")
		}
		if r, ok := readLabCounters(data); ok && accept(r) {
			return r
		}
		if pulse != nil {
			pulse()
		}
		select {
		case <-ctx.Done():
			t.Fatal("fresh numeric child report unavailable within rate-limit window")
			return labCounterReport{}
		case <-ticker.C:
		}
	}
}
func logLabCounters(t *testing.T, phase string, r labCounterReport) {
	t.Helper()
	b, _ := json.Marshal(r.Counters)
	t.Logf("child_counters phase=%s observed_unix_ms=%d counters=%s", phase, r.Time.UnixMilli(), b)
}

func labAlive(connections []net.Conn) int {
	alive := 0
	for _, c := range connections {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		var b [1]byte
		_, err := c.Read(b[:])
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			alive++
		}
	}
	return alive
}

func labHoldFlows(decoder *json.Decoder, encoder *json.Encoder, attempts int) int {
	if attempts < 1 || attempts > 516 {
		return 2
	}
	results := make(chan net.Conn, attempts)
	var workers sync.WaitGroup
	for range attempts {
		workers.Go(func() { c, _ := net.DialTimeout("tcp4", "1.1.1.1:443", 5*time.Second); results <- c })
	}
	workers.Wait()
	close(results)
	var held []net.Conn
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	result := labFixtureResult{}
	for c := range results {
		if c != nil {
			held = append(held, c)
			result.Open++
		} else {
			result.Refused++
		}
	}
	if encoder.Encode(result) != nil {
		return 3
	}
	for {
		var req labFixtureRequest
		if decoder.Decode(&req) != nil {
			return 3
		}
		switch req.Mode {
		case "check":
			if encoder.Encode(labFixtureResult{Alive: labAlive(held)}) != nil {
				return 3
			}
		case "extra":
			// Re-test the ceiling after the reserved DNS probe. Successful
			// extra connections are held too, so the ceiling stays full.
			extra := labFixtureResult{}
			for range min(max(req.Flows, 1), 16) {
				if c, err := net.DialTimeout("tcp4", "1.1.1.1:443", 5*time.Second); err == nil {
					held = append(held, c)
					extra.Open++
				} else {
					extra.Refused++
				}
			}
			if encoder.Encode(extra) != nil {
				return 3
			}
		case "done":
			return 0
		default:
			return 2
		}
	}
}

// The heartbeat is a locally answered AAAA query: it consumes reserved DNS
// capacity, generates a fresh report, and sends no upstream/public DNS traffic.
func labDNSPulse() error {
	c, err := net.DialTimeout("udp4", "192.0.2.1:53", time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	name, _ := dnsmessage.NewName("ipv4only.arpa.")
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: 1, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}}}
	wire, err := message.Pack()
	if err != nil {
		return err
	}
	if _, err := c.Write(wire); err != nil {
		return err
	}
	var buffer [512]byte
	count, err := c.Read(buffer[:])
	if err != nil {
		return err
	}
	if message.Unpack(buffer[:count]) != nil || message.ID != 1 || !message.Response || message.RCode != dnsmessage.RCodeSuccess || len(message.Answers) != 0 {
		return errors.New("invalid reserved DNS heartbeat")
	}
	return nil
}

func labFixtureStage(stage string, err error) {
	class, code := guestagent.DiagnosticError(err)
	_, _ = fmt.Fprintf(os.Stderr, "fixture_stage=%s error_class=%s exit_code=%d\n", stage, class, code)
}

func labGeneralFlows(s rootnet.Snapshot, ceiling int) (int, error) {
	if ceiling < 1 || ceiling > 512 {
		return 0, errors.New("lab ceiling must be 1..512")
	}
	limit := uint64(ceiling) // ceiling is positive and at most 512.
	if s.ActivePublicTCP > limit || s.ActiveUDP > limit || s.ActiveCache > limit {
		return 0, errors.New("invalid active-flow gauge")
	}
	total := s.ActivePublicTCP + s.ActiveUDP + s.ActiveCache
	if total > limit {
		return 0, errors.New("active gauges exceed general ceiling")
	}
	return int(total), nil //nolint:gosec // Each gauge and their sum are checked against the 1..512 ceiling.
}

func labLimitAttempts(s rootnet.Snapshot, ceiling int) (int, error) {
	used, err := labGeneralFlows(s, ceiling)
	if err != nil {
		return 0, err
	}
	if ceiling-used < 8 {
		return 0, errors.New("insufficient probe headroom; rerun with a larger lab ceiling")
	}
	// Background flows change between the report and the attempts. Attempting
	// the whole ceiling plus a margin guarantees refusals at any occupancy.
	return ceiling + 4, nil
}

func probeLabLimits(t *testing.T, parent context.Context, p *Provider, name, path string) {
	t.Helper()
	tool := labDNSTool(t, parent, p, name)
	if tool == "" {
		t.Log("limit_probes=skipped reason=DNS_verification_unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(parent, 240*time.Second)
	defer cancel()
	pulse := func() {
		input, _ := json.Marshal(labFixtureRequest{Mode: "dns-pulse"})
		if labExec(t, ctx, p, name, "reserved_dns_pulse", labFixtureArgs(), bytes.NewReader(input), io.Discard) != nil {
			t.Fatal("reserved DNS heartbeat failed")
		}
	}
	baselineStart := time.Now()
	before := waitLabCounters(t, ctx, path, func(r labCounterReport) bool { return !r.Time.Before(baselineStart) }, pulse)
	logLabCounters(t, "limits_background", before)
	if !before.gaugesPresent {
		t.Fatal("helper report lacks active gauges; rebuild the staged executable")
	}
	ceiling := p.cfg.Network.MaxFlows
	attempts, err := labLimitAttempts(*before.Counters, ceiling)
	if err != nil {
		t.Fatal(err)
	}
	background, _ := labGeneralFlows(*before.Counters, ceiling)
	t.Logf("limit_plan ceiling=%d background_active=%d background_tcp=%d background_udp=%d background_cache=%d attempts=%d", ceiling, background, before.Counters.ActivePublicTCP, before.Counters.ActiveUDP, before.Counters.ActiveCache, attempts)
	// Align the short connect-only occupancy phase with the next eligible helper
	// report. This preserves minute-limited production logging without requiring
	// idle public TLS peers to survive the whole logging interval.
	delay := time.Until(before.Time.Add(55 * time.Second))
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal("limit probe canceled before observation window")
		case <-timer.C:
		}
	}
	stream, stderr, err := labDuplex(t, ctx, p, name, "limits_start", labFixtureArgs())
	if err != nil {
		t.Fatal("limit fixture unavailable")
	}
	defer func() { _ = stream.Close(); _ = stderr.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	fail := func(phase string, err error) {
		labFixtureFailure(t, phase, err, stderr)
		t.Fatalf("limit fixture %s failed", phase)
	}
	decoder, encoder := json.NewDecoder(bufio.NewReader(stream)), json.NewEncoder(stream)
	exchange := func(req labFixtureRequest) labFixtureResult {
		if err := encoder.Encode(req); err != nil {
			fail("request", err)
		}
		var result labFixtureResult
		if err := decoder.Decode(&result); err != nil {
			fail("response", err)
		}
		return result
	}
	filledStart := time.Now()
	opened := exchange(labFixtureRequest{Mode: "limits", Flows: attempts})
	t.Logf("limit_connect ceiling=%d background_active=%d attempts=%d open=%d connect_errors=%d", ceiling, background, attempts, opened.Open, opened.Refused)
	if opened.Open < 1 || opened.Refused < 1 {
		t.Fatal("limit fixture did not both hold and refuse connections; inspect background gauges")
	}
	// Idle public TLS peers may close connect-only sockets within seconds, so
	// probe reserved DNS and re-test the ceiling at once, before any report wait.
	runLabDNS(t, ctx, p, name, tool, labDNSCases()[0])
	again := exchange(labFixtureRequest{Mode: "extra", Flows: 4})
	t.Logf("limit_recheck open=%d refused=%d", again.Open, again.Refused)
	if again.Refused < 1 {
		t.Fatal("flow ceiling was not full around the reserved DNS probe")
	}
	observation, stopObservation := context.WithTimeout(ctx, 25*time.Second)
	defer stopObservation()
	full := waitLabCounters(t, observation, path, func(r labCounterReport) bool { return !r.Time.Before(filledStart) }, pulse)
	logLabCounters(t, "limits_held", full)
	// Gauges are minute-rate reports and background UDP expires meanwhile, so
	// fullness is proven by refusals the ceiling counted, before and after DNS.
	if full.Counters.FlowLimit <= before.Counters.FlowLimit || full.Counters.AdmissionDenied != before.Counters.AdmissionDenied || full.Counters.DialFailed != before.Counters.DialFailed {
		t.Fatal("connect errors were not flow-ceiling refusals")
	}
	if err := encoder.Encode(labFixtureRequest{Mode: "done"}); err != nil {
		fail("release", err)
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		fail("completion", err)
	}
	t.Logf("limit_probe ceiling=%d background_active=%d attempts=%d open=%d connect_errors=%d active_public_tcp=%d active_udp=%d active_cache=%d dns_while_full=true refused_flow_increase=%d", ceiling, background, attempts, opened.Open, opened.Refused, full.Counters.ActivePublicTCP, full.Counters.ActiveUDP, full.Counters.ActiveCache, full.Counters.FlowLimit-before.Counters.FlowLimit)
}
