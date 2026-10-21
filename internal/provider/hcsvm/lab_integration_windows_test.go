//go:build windows && integration

package hcsvm

// TestLabNetworkBatch is lab batch 2: networked guests through the whole
// direct HCS stack. It runs the real VM host in this process (vmhost.Run, with
// its pipe, caller authorization and network guard) and drives it through this
// provider as the manager would: Create, WaitReady, then Delete. In between it
// probes the network from inside the guest. It is excluded from default tests:
// it needs the integration tag, an explicitly elevated launch and lab flags.
//
// Run it only with Windows CI drained. The guest's switch adds a host
// vEthernet adapter, which trips the App Sandbox broker's interface guard.
//
// Each run is a fresh production-sized cold boot:
//   - Create records the VM host's timings and which protect path ran.
//   - WaitReady applies the lease through the shared winrunner preflight and
//     prepare steps, which also prove the console and default desktop.
//   - The guest must reach public DNS, HTTPS and TCP. It must not reach its
//     gateway's DNS proxy, host listeners on the gateway, LAN and link-local
//     IPv6 addresses, public IPv6, or an optional operator-owned private peer.
//     Each host listener first proves itself reachable from the host, and
//     counts any connection from elsewhere.
//   - The guest must still be running after two guard intervals.
//   - Delete must leave the VM host without the guest and the host without
//     the guest's switch.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/vmhost"
	"golang.org/x/sys/windows"
)

var lab = struct {
	root, results, image, imageSHA256, guestName, guestUser *string
	helper, runnerDir, runnerArchive, runnerSHA256, peer    *string
	recoverRoot                                             *string
	runs                                                    *int
	drained                                                 *bool
}{
	root:          flag.String("lab.root", "", "new administrator-protected VM host directory (must not exist)"),
	recoverRoot:   flag.String("lab.recover-root", "", "an earlier lab root whose retained guests are settled first"),
	results:       flag.String("lab.results", "", "new results file (JSON lines); the VM host log goes beside it"),
	image:         flag.String("lab.image", "", "prepared image VHDX"),
	imageSHA256:   flag.String("lab.image-sha256", "", "prepared image SHA-256"),
	guestName:     flag.String("lab.guest-name", "", "prepared image's Windows computer name"),
	guestUser:     flag.String("lab.guest-user", "", "prepared image's console user"),
	helper:        flag.String("lab.helper", "", "bivouac.exe built from this checkout, sent as the guest adapter"),
	runnerDir:     flag.String("lab.runner-dir", `C:\actions-runner`, "runner directory in the guest"),
	runnerArchive: flag.String("lab.runner-archive", "", "optional official runner ZIP, when the image has no runner"),
	runnerSHA256:  flag.String("lab.runner-sha256", "", "runner ZIP SHA-256"),
	peer:          flag.String("lab.peer", "", "optional owner-controlled private peer ip:port the host can reach"),
	runs:          flag.Int("lab.runs", 2, "networked cold boots (1-4)"),
	drained:       flag.Bool("lab.windows-ci-drained", false, "operator confirms Windows CI is Off and drained"),
}

const (
	labController = "lab-network"
	labImage      = "lab"
	labCPU        = 4
	labMemoryMB   = 8192
)

// probeScript reads its fixed probe list on stdin and prints one bounded JSON
// object of probe name to outcome. Targets never reach a command line.
const probeScript = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$in=[Console]::In.ReadToEnd()|ConvertFrom-Json
$adapter=@(Get-NetAdapter|Where-Object{$_.MacAddress -ieq $in.mac})
if($adapter.Count -ne 1){exit 20}
$zone=[string]$adapter[0].ifIndex
$query=[byte[]](0x12,0x34,1,0,0,1,0,0,0,0,0,0,6)+[Text.Encoding]::ASCII.GetBytes('github')+[byte[]](3)+[Text.Encoding]::ASCII.GetBytes('com')+[byte[]](0,0,1,0,1)
function Get-Code($e){while($e.InnerException){$e=$e.InnerException};if($e -is [Net.Sockets.SocketException]){return [string]$e.SocketErrorCode};return 'failed'}
function Invoke-Probe($p){
  try{
    switch($p.kind){
      'dns'{if(@([Net.Dns]::GetHostAddresses($p.target)).Count -gt 0){return 'ok'};return 'empty'}
      'https'{
        $r=[Net.HttpWebRequest]::Create('https://'+$p.target+'/');$r.Timeout=10000;$r.AllowAutoRedirect=$false
        try{$r.GetResponse().Close();return 'ok'}catch{$e=$_.Exception;while($e -and !($e -is [Net.WebException])){$e=$e.InnerException};if($e -and $e.Response){$e.Response.Close();return 'ok'};return 'failed'}
      }
      'tcp'{
        $a=$p.target;if($p.link_local){$a=$a+'%'+$zone};$ip=[Net.IPAddress]::Parse($a)
        $c=New-Object Net.Sockets.TcpClient($ip.AddressFamily)
        try{if($c.ConnectAsync($ip,[int]$p.port).Wait(3000)){return 'ok'};return 'timeout'}catch{return Get-Code $_.Exception}finally{$c.Close()}
      }
      'udp-dns'{
        $ip=[Net.IPAddress]::Parse($p.target);$u=New-Object Net.Sockets.UdpClient($ip.AddressFamily);$u.Client.ReceiveTimeout=3000
        try{
          [void]$u.Send($query,$query.Length,(New-Object Net.IPEndPoint($ip,53)))
          $from=New-Object Net.IPEndPoint($ip,0);$b=$u.Receive([ref]$from)
          if($b.Length -ge 12 -and $b[0] -eq 0x12 -and $b[1] -eq 0x34){return 'ok'};return 'invalid'
        }catch{return Get-Code $_.Exception}finally{$u.Close()}
      }
    }
    return 'failed'
  }catch{return 'failed'}
}
$out=[ordered]@{}
foreach($p in $in.probes){$out[$p.name]=Invoke-Probe $p}
$out|ConvertTo-Json -Compress`

type probe struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Target    string `json:"target"`
	Port      int    `json:"port,omitempty"`
	LinkLocal bool   `json:"link_local,omitempty"`
	reach     bool   // the guest must reach it; otherwise it must not
}

type listenerResult struct {
	SelfTest bool `json:"self_test"`
	Foreign  int  `json:"foreign_connections"`
}

type networkRun struct {
	Run                  string                    `json:"run"`
	Passed               bool                      `json:"passed"`
	Failure              string                    `json:"failure,omitempty"`
	Timings              map[string]int64          `json:"timings_ms"`
	ProtectedBeforeStart bool                      `json:"protected_before_start"`
	Probes               map[string]string         `json:"probes,omitempty"`
	Listeners            map[string]listenerResult `json:"listeners,omitempty"`
	GuardSurvived        bool                      `json:"guard_survived"`
	SwitchRemoved        bool                      `json:"switch_removed"`
	Cleaned              bool                      `json:"cleaned"`
}

type results struct {
	mu sync.Mutex
	f  *os.File
}

func (r *results) write(t *testing.T, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err = r.f.Write(append(b, '\n')); err == nil {
		err = r.f.Sync()
	}
	if err != nil {
		t.Fatal(err)
	}
}

// recordingHost keeps the create response, which the provider discards.
type recordingHost struct {
	*vmhost.Client
	mu      sync.Mutex
	created vmhost.GuestInfo
}

func (h *recordingHost) Create(ctx context.Context, r vmhost.CreateRequest) (vmhost.GuestInfo, error) {
	g, err := h.Client.Create(ctx, r)
	h.mu.Lock()
	h.created = g
	h.mu.Unlock()
	return g, err
}

func TestLabNetworkBatch(t *testing.T) {
	if *lab.root == "" {
		t.Skip("lab flags not provided")
	}
	if !*lab.drained {
		t.Fatal("drain Windows CI first, then pass -lab.windows-ci-drained")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("lab batch requires an explicitly elevated launch")
	}
	if *lab.runs < 1 || *lab.runs > 4 || !filepath.IsAbs(*lab.helper) || (*lab.runnerArchive == "") != (*lab.runnerSHA256 == "") {
		t.Fatal("lab needs 1-4 runs, an absolute helper path, and a runner archive only with its SHA-256")
	}
	if b, err := hex.DecodeString(*lab.imageSHA256); err != nil || len(b) != 32 {
		t.Fatal("lab image pin must be a SHA-256 value")
	}
	if _, err := os.Lstat(*lab.root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("lab root must not exist yet; the VM host creates it protected")
	}
	var peer netip.AddrPort
	if *lab.peer != "" {
		var err error
		if peer, err = netip.ParseAddrPort(*lab.peer); err != nil || !peer.Addr().Is4() || !peer.Addr().IsPrivate() {
			t.Fatal("lab peer must be a private IPv4 ip:port")
		}
	}
	f, err := os.OpenFile(*lab.results, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("results file must be new:", err)
	}
	defer func() { _ = f.Close() }()
	out := &results{f: f}
	logFile, err := os.OpenFile(*lab.results+".vmhost.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("VM host log must be new:", err)
	}
	defer func() { _ = logFile.Close() }()
	out.write(t, map[string]any{"event": "start", "at": time.Now().UTC().Format(time.RFC3339), "runs": *lab.runs, "peer": *lab.peer != ""})
	defer func() {
		out.write(t, map[string]any{"event": "end", "failed": t.Failed(), "at": time.Now().UTC().Format(time.RFC3339)})
	}()

	started := time.Now()
	pin, err := pinImage(*lab.image, *lab.imageSHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(pin) }()
	out.write(t, map[string]any{"event": "image-verified", "ms": time.Since(started).Milliseconds()})
	if *lab.recoverRoot != "" {
		started := time.Now()
		err := recoverLab(*lab.recoverRoot)
		event := map[string]any{"event": "recovered", "ms": time.Since(started).Milliseconds(), "pool_interfaces": poolInterfaces()}
		if err != nil {
			event["error"] = err.Error()
		}
		out.write(t, event)
		if err != nil || event["pool_interfaces"] != 0 {
			t.Fatal("the earlier lab root still retains a guest or network; no guest started")
		}
	}

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	cfg := vmhost.Config{Root: *lab.root, Controller: labController, Accounts: []string{user.User.Sid.String()},
		Images: map[string]string{labImage: *lab.image}, MaxInstances: 1, MaxCPU: labCPU, MaxMemoryMB: labMemoryMB}
	serveCtx, stopHost := context.WithCancel(context.Background())
	var runErr error
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		runErr = vmhost.Run(serveCtx, cfg, slog.New(slog.NewJSONHandler(logFile, nil)))
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			stopHost()
			<-exited
			if runErr != nil {
				t.Error("VM host exit:", runErr)
			}
		})
	}
	defer stop()
	host := &recordingHost{Client: vmhost.NewClient()}
	if err := waitForHost(host, exited); err != nil {
		t.Fatal(err)
	}
	p, err := New(Options{Name: "lab", ControllerID: labController, Image: labImage, GuestName: *lab.guestName, GuestUser: *lab.guestUser,
		CPU: labCPU, MemoryMB: labMemoryMB, GPU: true, RunnerDir: *lab.runnerDir, RunnerArchive: *lab.runnerArchive, RunnerSHA256: *lab.runnerSHA256,
		Helper: *lab.helper, StateDir: t.TempDir()}, host, NewTransport(*lab.guestUser))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	for i := range *lab.runs {
		if err := checkReserves(*lab.root); err != nil {
			out.write(t, networkRun{Run: "network-" + strconv.Itoa(i+1), Failure: err.Error()})
			t.Error(err)
			break
		}
		r := runNetworked(p, host, "network-"+strconv.Itoa(i+1), peer)
		out.write(t, r)
		if !r.Passed {
			t.Errorf("%s: %s", r.Run, r.Failure)
		}
		if !r.Cleaned {
			t.Error("guest retained; stopping the batch")
			break
		}
	}
	stop()
	entries, err := os.ReadDir(*lab.root)
	if err != nil {
		t.Error(err)
	}
	for _, e := range entries {
		if e.Name() != "daemon.lock" {
			t.Error("VM host root retained", e.Name())
		}
	}
	if leftover := poolInterfaces(); leftover != 0 {
		t.Error("host still has interfaces in the VM host's subnet pool:", leftover)
	}
}

// runNetworked boots one networked guest through the provider and proves its
// network. Cleanup runs regardless of failure and must confirm absence.
func runNetworked(p *Provider, host *recordingHost, label string, peer netip.AddrPort) (r networkRun) {
	r = networkRun{Run: label, Timings: map[string]int64{}}
	var id [4]byte
	if _, err := rand.Read(id[:]); err != nil {
		r.Failure = err.Error()
		return r
	}
	instance := hex.EncodeToString(id[:])
	spec := provider.Spec{Name: p.prefix() + instance, Meta: provider.Metadata{ControllerID: labController, InstanceID: instance, CreatedAt: time.Now().UTC().Format(time.RFC3339)}}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	ms := func(d time.Duration) int64 { return d.Milliseconds() }
	started := time.Now()
	err := p.Create(ctx, spec)
	r.Timings["create_total"] = ms(time.Since(started))
	host.mu.Lock()
	created := host.created
	host.mu.Unlock()
	for k, v := range created.TimingsMS {
		r.Timings[k] = v
	}
	r.ProtectedBeforeStart = created.ProtectedBeforeStart
	defer func() {
		cleanup := time.Now()
		cleanCtx, done := context.WithTimeout(context.Background(), 5*time.Minute)
		defer done()
		err := p.Delete(cleanCtx, spec.Name)
		r.Timings["delete"] = ms(time.Since(cleanup))
		deleteErr := err
		if err == nil || errors.Is(err, provider.ErrNotFound) {
			// Absent to this account and holding no reservation: a failed
			// create whose cleanup failed is invisible but still reserved.
			_, err = host.Status(cleanCtx, spec.Name)
			info, infoErr := host.Info(cleanCtx)
			r.Cleaned = vmhost.IsCode(err, vmhost.CodeNotFound) && infoErr == nil && info.Running == 0
		}
		// VM host errors are host text, never guest output.
		if !r.Cleaned && r.Failure == "" {
			r.Failure = "delete: guest not confirmed absent"
			if deleteErr != nil {
				r.Failure += ": " + deleteErr.Error()
			}
		}
		if created.Network != nil {
			r.SwitchRemoved = waitInterfaceGone(cleanCtx, created.Network.Gateway)
			if !r.SwitchRemoved && r.Failure == "" {
				r.Failure = "delete: guest switch adapter remained"
			}
		}
		r.Passed = r.Passed && r.Cleaned && (created.Network == nil || r.SwitchRemoved)
	}()
	fail := func(stage string, err error) networkRun {
		r.Failure = stage + ": " + err.Error()
		return r
	}
	if err != nil {
		return fail("create", err)
	}
	if created.Network == nil {
		return fail("create", errors.New("no network lease"))
	}
	gateway, err := netip.ParseAddr(created.Network.Gateway)
	if err != nil {
		return fail("lease", err)
	}
	readyStarted := time.Now()
	if err = p.WaitReady(ctx, spec.Name); err != nil {
		return fail("wait ready", err)
	}
	r.Timings["wait_ready"] = ms(time.Since(readyStarted))

	listeners, probes, err := targets(ctx, gateway, peer)
	defer func() {
		for _, l := range listeners {
			l.close()
		}
	}()
	if err != nil {
		return fail("host targets", err)
	}
	stdin, err := json.Marshal(map[string]any{"mac": created.Network.MAC, "probes": probes})
	if err != nil {
		return fail("probes", err)
	}
	probeStarted := time.Now()
	output, err := p.run(ctx, spec.Name, "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "+encodedPowerShell(probeScript), stdin, 8192)
	r.Timings["probes"] = ms(time.Since(probeStarted))
	if err != nil {
		return fail("probes", err)
	}
	if r.Probes, err = outcomes(output, probes); err != nil {
		return fail("probes", err)
	}
	r.Listeners = map[string]listenerResult{}
	for name, l := range listeners {
		r.Listeners[name] = l.result()
	}

	// Two guard passes must leave the guest running: its layer survived boot,
	// readiness and the probes.
	guardStarted := time.Now()
	select {
	case <-ctx.Done():
		return fail("guard", ctx.Err())
	case <-time.After(2*vmhost.GuardInterval + 5*time.Second):
	}
	st, err := p.Status(ctx, spec.Name)
	r.Timings["guard_wait"] = ms(time.Since(guardStarted))
	r.GuardSurvived = err == nil && st.Exists && st.Running && st.Owned
	if !r.GuardSurvived {
		return fail("guard", errors.Join(err, errors.New("guest was quarantined or lost")))
	}

	for _, pr := range probes {
		if got := r.Probes[pr.Name]; (got == "ok") != pr.reach {
			return fail("probes", fmt.Errorf("%s: %s", pr.Name, got))
		}
	}
	for name, l := range r.Listeners {
		if l.Foreign != 0 {
			return fail("listeners", fmt.Errorf("%s accepted %d foreign connections", name, l.Foreign))
		}
	}
	r.Passed = true
	return r
}

// targets starts host listeners and returns the probe list. The listeners
// bind the gateway (the host's side of the guest switch), the host's LAN
// source address and the switch adapter's IPv6 link-local address.
func targets(ctx context.Context, gateway netip.Addr, peer netip.AddrPort) (map[string]*listener, []probe, error) {
	probes := []probe{
		{Name: "public-dns", Kind: "dns", Target: "github.com", reach: true},
		{Name: "public-https", Kind: "https", Target: "api.github.com", reach: true},
		{Name: "public-tcp", Kind: "tcp", Target: "1.1.1.1", Port: 443, reach: true},
		{Name: "public-udp-dns", Kind: "udp-dns", Target: "1.1.1.1", reach: true},
		{Name: "gateway-dns-proxy", Kind: "udp-dns", Target: gateway.String()},
		{Name: "public-ipv6-tcp", Kind: "tcp", Target: "2606:4700:4700::1111", Port: 443},
	}
	listeners := map[string]*listener{}
	adapter, err := waitInterface(ctx, gateway)
	if err != nil {
		return listeners, nil, err
	}
	lan, err := lanAddress()
	if err != nil {
		return listeners, nil, err
	}
	linkLocal, err := linkLocalAddress(adapter)
	if err != nil {
		return listeners, nil, err
	}
	for _, target := range []struct {
		name string
		addr netip.Addr
		zone bool
	}{{"gateway-tcp", gateway, false}, {"host-lan-tcp", lan, false}, {"host-link-local-tcp", linkLocal, true}} {
		zone := ""
		if target.zone {
			zone = strconv.Itoa(adapter.Index)
		}
		l, err := listen(target.addr, zone)
		if err != nil {
			return listeners, nil, fmt.Errorf("%s listener: %w", target.name, err)
		}
		listeners[target.name] = l
		probes = append(probes, probe{Name: target.name, Kind: "tcp", Target: target.addr.String(), Port: l.port, LinkLocal: target.zone})
	}
	if peer.IsValid() {
		c, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", peer.String())
		if err != nil {
			return listeners, nil, fmt.Errorf("private peer is not reachable from the host: %w", err)
		}
		_ = c.Close()
		probes = append(probes, probe{Name: "private-peer-tcp", Kind: "tcp", Target: peer.Addr().String(), Port: int(peer.Port())})
	}
	return listeners, probes, nil
}

// outcomes maps the guest's report onto a fixed vocabulary, so nothing
// guest-controlled reaches the results.
func outcomes(output []byte, probes []probe) (map[string]string, error) {
	var raw map[string]string
	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, errors.New("invalid bounded probe report")
	}
	got := map[string]string{}
	for _, p := range probes {
		v, ok := raw[p.Name]
		if !ok {
			return nil, errors.New("probe report incomplete")
		}
		switch v {
		case "ok", "timeout", "failed", "empty", "invalid":
		case "ConnectionRefused":
			v = "refused"
		case "TimedOut":
			v = "timeout"
		case "NetworkUnreachable", "HostUnreachable", "AddressNotAvailable":
			v = "unreachable"
		case "AccessDenied":
			v = "denied"
		default:
			v = "other"
		}
		got[p.Name] = v
	}
	if len(raw) != len(probes) {
		return nil, errors.New("probe report has unknown entries")
	}
	return got, nil
}

func TestLabProbeOutcomesUseAFixedVocabulary(t *testing.T) {
	probes := []probe{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}}
	got, err := outcomes([]byte(`{"a":"ok","b":"ConnectionRefused","c":"TimedOut","d":"<guest text>"}`), probes)
	if err != nil || got["a"] != "ok" || got["b"] != "refused" || got["c"] != "timeout" || got["d"] != "other" {
		t.Fatal("outcomes", got, err)
	}
	for _, bad := range []string{`{"a":"ok"}`, `{"a":"ok","b":"ok","c":"ok","d":"ok","e":"ok"}`, `not json`} {
		if _, err := outcomes([]byte(bad), probes); err == nil {
			t.Fatal("accepted an incomplete or unknown probe report", bad)
		}
	}
}

type listener struct {
	l     *net.TCPListener
	local netip.Addr
	port  int
	mu    sync.Mutex
	self  int
	other int
	ok    bool
	done  chan struct{}
}

// listen accepts on addr, counting connections from addr itself apart from
// any other source, and proves it is reachable from the host.
func listen(addr netip.Addr, zone string) (*listener, error) {
	tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: addr.AsSlice(), Zone: zone})
	if err != nil {
		return nil, err
	}
	l := &listener{l: tcp, local: addr, port: tcp.Addr().(*net.TCPAddr).Port, done: make(chan struct{})}
	go func() {
		defer close(l.done)
		for {
			c, err := tcp.AcceptTCP()
			if err != nil {
				return
			}
			remote, _ := netip.AddrFromSlice(c.RemoteAddr().(*net.TCPAddr).IP)
			l.mu.Lock()
			if remote.Unmap() == addr {
				l.self++
			} else {
				l.other++
			}
			l.mu.Unlock()
			_ = c.Close()
		}
	}()
	c, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", tcp.Addr().String())
	if err == nil {
		_ = c.Close()
		for range 20 {
			l.mu.Lock()
			l.ok = l.self > 0
			l.mu.Unlock()
			if l.ok {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return l, nil
}

func (l *listener) result() listenerResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	return listenerResult{SelfTest: l.ok, Foreign: l.other}
}

func (l *listener) close() {
	_ = l.l.Close()
	<-l.done
}

// waitInterface finds the host adapter that holds addr: the guest switch's
// host side, which appears once the VM host creates the switch.
func waitInterface(ctx context.Context, addr netip.Addr) (net.Interface, error) {
	for {
		if adapter, ok := interfaceWith(addr); ok {
			return adapter, nil
		}
		select {
		case <-ctx.Done():
			return net.Interface{}, errors.New("guest switch adapter not found on the host")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func waitInterfaceGone(ctx context.Context, address string) bool {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	for {
		if _, ok := interfaceWith(addr); !ok {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func interfaceWith(addr netip.Addr) (net.Interface, bool) {
	adapters, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, false
	}
	for _, adapter := range adapters {
		addresses, err := adapter.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addresses {
			if prefix, err := netip.ParsePrefix(a.String()); err == nil && prefix.Addr() == addr {
				return adapter, true
			}
		}
	}
	return net.Interface{}, false
}

// poolInterfaces counts host addresses inside the VM host's 10.251.0.0/16.
func poolInterfaces() int {
	pool := netip.MustParsePrefix("10.251.0.0/16")
	adapters, err := net.Interfaces()
	if err != nil {
		return -1
	}
	n := 0
	for _, adapter := range adapters {
		addresses, err := adapter.Addrs()
		if err != nil {
			return -1
		}
		for _, a := range addresses {
			if prefix, err := netip.ParsePrefix(a.String()); err == nil && pool.Contains(prefix.Addr()) {
				n++
			}
		}
	}
	return n
}

// lanAddress is the host's source address for public IPv4. A UDP connect
// selects a route without sending anything.
func lanAddress() (netip.Addr, error) {
	c, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = c.Close() }()
	addr, ok := netip.AddrFromSlice(c.LocalAddr().(*net.UDPAddr).IP)
	if !ok {
		return netip.Addr{}, errors.New("no host LAN address")
	}
	return addr.Unmap(), nil
}

func linkLocalAddress(adapter net.Interface) (netip.Addr, error) {
	addresses, err := adapter.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addresses {
		if prefix, err := netip.ParsePrefix(a.String()); err == nil && prefix.Addr().Is6() && prefix.Addr().IsLinkLocalUnicast() {
			return prefix.Addr().WithZone(""), nil
		}
	}
	return netip.Addr{}, errors.New("guest switch adapter has no IPv6 link-local address")
}

// waitForHost waits for the in-process VM host to serve its pipe; Recover
// runs first and is bounded to 2 minutes.
func waitForHost(host *recordingHost, exited <-chan struct{}) error {
	deadline := time.Now().Add(3 * time.Minute)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		info, err := host.Info(ctx)
		cancel()
		if err == nil && info.Controller == labController {
			return nil
		}
		select {
		case <-exited:
			return errors.New("VM host exited during startup; see its log")
		case <-time.After(500 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.Join(errors.New("VM host did not start serving"), err)
		}
	}
}

// recoverLab settles an earlier lab root's retained guests and networks with
// a VM host of the same controller, as its next start would.
func recoverLab(root string) error {
	h, err := vmhost.Open(root, labController)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return errors.Join(h.Recover(ctx), h.Close())
}

// checkReserves leaves the host room beyond the guest, as batch 1 did.
func checkReserves(root string) error {
	s, err := perf.NewSampler(root).Sample()
	if err != nil {
		return err
	}
	if s.AvailableBytes < (labMemoryMB+6<<10)<<20 || s.Commit == nil || s.Commit.HeadroomBytes() < (labMemoryMB+4<<10)<<20 {
		return errors.New("host reserves unavailable; no guest started")
	}
	return nil
}

// pinImage holds a handle that denies writers and deletion for the whole
// batch, then verifies the image hash through a second read-only handle. The
// pin is never wrapped in an os.File, whose finalizer could close it.
func pinImage(path, sha string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return 0, fmt.Errorf("cannot pin image: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		_ = windows.CloseHandle(h)
		return 0, err
	}
	defer func() { _ = f.Close() }()
	sum := sha256.New()
	if _, err = io.Copy(sum, f); err != nil || !strings.EqualFold(hex.EncodeToString(sum.Sum(nil)), sha) {
		_ = windows.CloseHandle(h)
		return 0, errors.New("prepared image SHA-256 differs")
	}
	return h, nil
}

func encodedPowerShell(s string) string {
	words := windows.StringToUTF16(s)
	b := make([]byte, 0, len(words)*2)
	for _, w := range words[:len(words)-1] {
		b = binary.LittleEndian.AppendUint16(b, w)
	}
	return base64.StdEncoding.EncodeToString(b)
}
