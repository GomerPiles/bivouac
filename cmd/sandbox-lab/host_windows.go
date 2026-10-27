//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/command"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/winhost"
	"github.com/GomerPiles/bivouac/internal/winrunner"
	"golang.org/x/sys/windows"
)

//go:embed bootstrap.ps1
var bootstrapScript string

type sandboxConfig struct {
	XMLName    xml.Name       `xml:"Configuration"`
	Networking string         `xml:"Networking"`
	GPU        string         `xml:"vGPU"`
	Audio      string         `xml:"AudioInput"`
	Video      string         `xml:"VideoInput"`
	Printers   string         `xml:"PrinterRedirection"`
	Clipboard  string         `xml:"ClipboardRedirection"`
	Memory     int            `xml:"MemoryInMB"`
	Folders    []mappedFolder `xml:"MappedFolders>MappedFolder"`
	Logon      string         `xml:"LogonCommand>Command"`
}
type mappedFolder struct {
	Host     string `xml:"HostFolder"`
	Guest    string `xml:"SandboxFolder"`
	ReadOnly bool   `xml:"ReadOnly"`
}

func newConfig(input, output string, network bool) sandboxConfig {
	mode := "Disable"
	if network {
		mode = "Enable"
	}
	return sandboxConfig{Networking: mode, GPU: "Disable", Audio: "Disable", Video: "Disable", Printers: "Disable", Clipboard: "Disable", Memory: 4096, Folders: []mappedFolder{{input, bootstrapDirectory, true}, {output, reportDirectory, false}}, Logon: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\BivouacBootstrap\bootstrap.ps1`}
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&15 | 64
	raw[8] = raw[8]&63 | 128
	text := hex.EncodeToString(raw[:])
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:], nil
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return errors.New("lab JSON unavailable")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return errors.New("lab state directory unavailable")
	}
	defer func() { _ = root.Close() }()
	name := filepath.Base(path)
	tmp := name + ".new"
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("fresh lab state staging required")
	}
	defer func() { _ = root.Remove(tmp) }()
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return errors.New("lab state flush failed")
	}
	if err := root.Rename(tmp, name); err != nil {
		return errors.New("lab state replacement failed")
	}
	return nil
}

func copyAsset(source, target string, limit int64) error {
	in, err := os.Open(source)
	if err != nil {
		return errors.New("lab asset unavailable")
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return errors.New("lab asset refused")
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("fresh lab asset required")
	}
	n, copyErr := io.Copy(out, io.LimitReader(in, limit+1))
	err = errors.Join(copyErr, out.Close())
	if err != nil || n != info.Size() {
		return errors.New("lab asset copy incomplete")
	}
	return nil
}

type labHost struct {
	binary, input, output string
	record                labRecord
	client                tls.Certificate
	secure                bool
}

func (h *labHost) call(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if len(args) > 0 && args[0] == "connect" {
		// The desktop client inherits the CLI's handles and outlives it. Real
		// NUL handles avoid holding Go's output-copy pipes open until UI exit.
		nul, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			return nil, errors.New("desktop NUL streams unavailable")
		}
		defer func() { _ = nul.Close() }()
		cmd := exec.CommandContext(ctx, h.binary, append(args, "--raw")...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = nul, nul, nul
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.WaitDelay = 3 * time.Second
		if cmd.Run() != nil {
			return nil, errors.New("sandbox desktop command failed")
		}
		return nil, nil
	}
	return (command.Native{}).Output(ctx, h.binary, append(args, "--raw"))
}
func (h *labHost) contains(ctx context.Context) error {
	data, err := h.call(ctx, "list")
	if err != nil {
		return err
	}
	ids, err := listed(data)
	if err != nil {
		return err
	}
	if !slices.Contains(ids, h.record.ID) {
		return errors.New("recorded Sandbox absent")
	}
	return nil
}
func (h *labHost) prove(ctx context.Context) error {
	if !h.record.valid() || h.record.Phase != "started" {
		return errors.New("sandbox has no start receipt")
	}
	if err := h.contains(ctx); err != nil {
		return err
	}
	request, err := newID()
	if err != nil {
		return err
	}
	// This public challenge is consumed only after close and explicit exec.
	// Sandbox's mapped-folder service can hold deny-delete handles, so it is
	// deliberately not durable state and does not use rename publication.
	requestData, err := json.Marshal(struct {
		ID string `json:"id"`
	}{request})
	if err != nil {
		return errors.New("encode ownership challenge")
	}
	if err := os.WriteFile(filepath.Join(h.input, "request.json"), requestData, 0o600); err != nil {
		return errors.New("publish public ownership challenge")
	}
	data, err := h.call(ctx, "exec", "--id", h.record.ID, "--command", `"C:\Program Files\Bivouac\sandbox-lab.exe" ownership`, "--run-as", "ExistingLogin")
	if err != nil {
		return errors.New("live Sandbox ownership unavailable")
	}
	var exit struct {
		Code *int `json:"ExitCode"`
	}
	if decodeBounded(bytes.NewReader(data), &exit) != nil || exit.Code == nil || *exit.Code != 0 {
		return errors.New("sandbox ownership command refused")
	}
	var proof ownershipProof
	if readJSON(filepath.Join(h.output, "ownership.json"), &proof) != nil || !h.record.accepts(proof, request) {
		return errors.New("sandbox guest proof differs")
	}
	h.record.Boot = proof.Boot
	return writeJSON(filepath.Join(filepath.Dir(h.input), "record.json"), h.record)
}

func (h *labHost) stop(ctx context.Context) error {
	if err := h.prove(ctx); err != nil {
		return err
	}
	if h.record.Native != nil {
		if err := h.proveNative(ctx); err != nil {
			return err
		}
	}
	if _, err := h.call(ctx, "stop", "--id", h.record.ID); err != nil {
		return errors.New("sandbox stop uncertain; retain record")
	}
	for {
		data, err := h.call(ctx, "list")
		if err != nil {
			return err
		}
		ids, err := listed(data)
		if err != nil {
			return err
		}
		if !slices.Contains(ids, h.record.ID) {
			h.record.Phase = "stopped"
			return writeJSON(filepath.Join(filepath.Dir(h.input), "record.json"), h.record)
		}
		if pause(ctx) != nil {
			return errors.New("sandbox absence unconfirmed; retain record")
		}
	}
}

func pause(ctx context.Context) error {
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type bootFacts struct {
	Stage  int         `json:"stage"`
	Failed bool        `json:"failed"`
	Smoke  *smokeFacts `json:"smoke,omitempty"`
}
type labResult struct {
	NetworkProbe           bool               `json:"network_probe"`
	ReverseProbe           bool               `json:"reverse_probe"`
	Bootstrap              bool               `json:"bootstrap"`
	Ownership              bool               `json:"ownership"`
	Agent                  bool               `json:"agent"`
	TLS                    bool               `json:"tls"`
	TCP                    bool               `json:"tcp"`
	DialError              string             `json:"dial_error,omitempty"`
	AgentError             string             `json:"agent_error,omitempty"`
	AgentExit              int                `json:"agent_exit,omitempty"`
	UnauthenticatedRefused bool               `json:"unauthenticated_refused"`
	Stopped                bool               `json:"stopped"`
	CreateMS               int64              `json:"create_ms"`
	ReadyMS                int64              `json:"ready_ms"`
	TeardownMS             int64              `json:"teardown_ms"`
	Native                 bool               `json:"native"`
	NativeLoopbackRefused  bool               `json:"native_loopback_refused"`
	NativeExit             bool               `json:"native_exit"`
	NativeCancellation     bool               `json:"native_cancellation"`
	NativeRestart          bool               `json:"native_restart"`
	Secure                 bool               `json:"secure"`
	MissingClientRefused   bool               `json:"missing_client_refused"`
	WrongClientRefused     bool               `json:"wrong_client_refused"`
	WrongServerRefused     bool               `json:"wrong_server_refused"`
	PlaintextRefused       bool               `json:"plaintext_refused"`
	Anonymous              *anonymousFacts    `json:"anonymous,omitempty"`
	DiscoveryChecked       bool               `json:"discovery_checked"`
	Discovery              []discoveryAttempt `json:"discovery,omitempty"`
	Smoke                  *smokeFacts        `json:"smoke,omitempty"`
}

func runLab(ctx context.Context, args []string, out io.Writer) (retErr error) {
	flags := flag.NewFlagSet("sandbox-lab run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	base := flags.String("root", "", "existing directory for fresh isolated lab state")
	bivouac := flags.String("bivouac", "", "matching host-built executable")
	runner := flags.String("runner", "", "official Windows x64 runner ZIP")
	digest := flags.String("runner-sha256", "", "pinned official ZIP digest")
	network := flags.Bool("network-probe", false, "enable default networking for trusted probes only; never registers a runner")
	reverse := flags.Bool("reverse-probe", false, "test guest-initiated authenticated transport; implies network-probe")
	hold := flags.Duration("hold", 0, "hold a proven guest for read-only external inspection (maximum 3 minutes)")
	native := flags.Bool("native-probe", false, "request one read-only UAC discovery and test the ordinary-user HvSocket channel with networking disabled")
	secure := flags.Bool("secure-probe", false, "use per-launch mutual TLS for the native probe; requests read-only UAC discovery")
	discovery := flags.Bool("discovery-probe", false, "try guest-local runtime UUID sources with no UAC or native enumeration")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *base == "" || *bivouac == "" || *runner == "" {
		return errors.New("run requires --root, --bivouac, --runner and --runner-sha256")
	}
	if *reverse {
		*network = true
	}
	if *secure {
		*native = true
	}
	if *hold < 0 || *hold > 3*time.Minute {
		return errors.New("inspection hold must be between zero and three minutes")
	}
	if *native && (*network || *reverse) {
		return errors.New("native probe requires networking disabled")
	}
	if *discovery && (*native || *network) {
		return errors.New("discovery probe requires a separate offline run")
	}
	if (*native || *discovery) && windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("native and discovery probe managers must remain unelevated")
	}
	var reverseSocket *net.TCPListener
	if *reverse {
		// #nosec G102 -- Explicit lab control listener; exact guest IP and mutual TLS are both required. No host firewall rule is installed.
		listener, err := net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			return errors.New("lab reverse listener unavailable")
		}
		reverseSocket = listener.(*net.TCPListener)
		defer func() { _ = reverseSocket.Close() }()
	}
	if len(*digest) != 64 || strings.Trim(*digest, "0123456789abcdef") != "" || winrunner.VerifyArchive(*runner, *digest) != nil {
		return errors.New("pinned runner verification failed")
	}
	binary, err := exec.LookPath("wsb.exe")
	if err != nil {
		return errors.New("sandbox CLI unavailable")
	}
	data, err := (command.Native{}).Output(ctx, binary, []string{"list", "--raw"})
	if err != nil {
		return err
	}
	ids, err := listed(data)
	if err != nil {
		return err
	}
	if len(ids) != 0 {
		return errors.New("sandbox slot occupied; existing instances are never stopped")
	}
	// Native elevation has an independent working directory. Keep mappings,
	// helper executable and receipt arguments absolute across that boundary.
	absoluteBase, err := filepath.Abs(*base)
	if err != nil {
		return errors.New("absolute lab directory unavailable")
	}
	root, err := winhost.PrivateDirectory(absoluteBase)
	if err != nil {
		return errors.New("private lab directory unavailable")
	}
	id, err := newID()
	if err != nil {
		return err
	}
	h := labHost{binary: binary, input: filepath.Join(root, "input"), output: filepath.Join(root, "output"), record: labRecord{Name: "bivouac-sandbox-" + id, ID: id, Phase: "planned"}, secure: *secure}
	for _, dir := range []string{h.input, h.output} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return errors.New("create lab staging")
		}
	}
	self, err := os.Executable()
	if err != nil {
		return errors.New("lab executable unavailable")
	}
	for _, asset := range [][2]string{{self, "sandbox-lab.exe"}, {*bivouac, "bivouac.exe"}, {*runner, "runner.zip"}} {
		if err := copyAsset(asset[0], filepath.Join(h.input, asset[1]), 512<<20); err != nil {
			return err
		}
	}
	if err := winrunner.VerifyArchive(filepath.Join(h.input, "runner.zip"), *digest); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(h.input, "bootstrap.ps1"), []byte(bootstrapScript), 0o600); err != nil {
		return errors.New("publish lab bootstrap")
	}
	for _, path := range []string{filepath.Join(root, "record.json"), filepath.Join(h.input, "record.json")} {
		if err := writeJSON(path, h.record); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(h.input, "settings.json"), struct {
		Network bool   `json:"network_probe"`
		Reverse bool   `json:"reverse_probe"`
		Digest  string `json:"runner_sha256"`
		Secure  bool   `json:"secure_probe"`
	}{*network, *reverse, *digest, *secure}); err != nil {
		return err
	}
	var client tls.Certificate
	if *network || *secure {
		var public []byte
		client, public, err = certificate(true)
		if err != nil {
			return errors.New("client TLS setup failed")
		}
		if err := os.WriteFile(filepath.Join(h.input, "client.pem"), public, 0o600); err != nil {
			return errors.New("publish public client certificate")
		}
		h.client = client
	}
	config, err := xml.Marshal(newConfig(h.input, h.output, *network))
	if err != nil {
		return errors.New("sandbox XML unavailable")
	}
	created := time.Now()
	data, err = h.call(ctx, "start", "--id", id, "--config", string(config))
	if err != nil {
		return errors.New("sandbox launch uncertain; retain planned record")
	}
	var receipt struct {
		ID string `json:"Id"`
	}
	if decodeBounded(bytes.NewReader(data), &receipt) != nil || receipt.ID != id {
		return errors.New("sandbox start receipt differs; retain planned record")
	}
	h.record.Phase = "started"
	if err := writeJSON(filepath.Join(root, "record.json"), h.record); err != nil {
		return err
	}
	result := labResult{NetworkProbe: *network, ReverseProbe: *reverse, CreateMS: time.Since(created).Milliseconds()}
	defer func() {
		begun := time.Now()
		cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if err := h.stop(cleanup); err != nil {
			retErr = errors.Join(retErr, errors.New("sandbox cleanup lacks proof; lab record retained"))
		} else {
			result.Stopped = true
		}
		result.TeardownMS = time.Since(begun).Milliseconds()
		if err := writeJSON(filepath.Join(root, "result.json"), result); err != nil {
			retErr = errors.Join(retErr, err)
		}
		if err := json.NewEncoder(out).Encode(result); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	if _, err := h.call(ctx, "connect", "--id", id); err != nil {
		return errors.New("sandbox desktop unavailable")
	}
	var boot bootFacts
	for readJSON(filepath.Join(h.output, "boot.json"), &boot) != nil {
		if pause(ctx) != nil {
			return errors.New("sandbox bootstrap timed out")
		}
	}
	if boot.Failed || boot.Stage != 5 {
		return fmt.Errorf("sandbox bootstrap failed at stage %d", boot.Stage)
	}
	result.Bootstrap = true
	result.Smoke = boot.Smoke
	result.ReadyMS = time.Since(created).Milliseconds()
	if boot.Smoke == nil || !boot.Smoke.valid(*network) {
		return errors.New("sandbox direct smoke predicates failed")
	}
	if err := h.prove(ctx); err != nil {
		return err
	}
	result.Ownership = true
	if *discovery {
		return h.discoveryProbe(ctx, &result)
	}
	if *native {
		return h.nativeProbe(ctx, self, &result)
	}
	if *hold > 0 {
		timer := time.NewTimer(*hold)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	if !*network {
		return nil
	}
	var report tcpReport
	for readJSON(filepath.Join(h.output, "tcp.json"), &report) != nil {
		if pause(ctx) != nil {
			return errors.New("sandbox TCP readiness timed out")
		}
	}
	if report.ID != id || report.Name != h.record.Name || report.Boot != h.record.Boot || (!*reverse && report.Port < 1) || report.Port > 65535 || len(report.Fingerprint) != 64 || !report.Session.valid() {
		return errors.New("sandbox TCP report refused")
	}
	data, err = h.call(ctx, "ip", "--id", id)
	if err != nil {
		return errors.New("sandbox IP unavailable")
	}
	var ip struct {
		Networks []struct {
			IP string `json:"IpV4Address"`
		} `json:"Networks"`
	}
	if decodeBounded(bytes.NewReader(data), &ip) != nil || len(ip.Networks) != 1 || net.ParseIP(ip.Networks[0].IP).To4() == nil {
		return errors.New("sandbox IPv4 response unavailable")
	}
	address := net.JoinHostPort(ip.Networks[0].IP, fmt.Sprint(report.Port))
	var reverseRaw guestagent.Dialer
	if *reverse {
		interfaces, err := net.Interfaces()
		if err != nil {
			return errors.New("reverse host inventory unavailable")
		}
		var addresses []string
		for _, adapter := range interfaces {
			items, err := adapter.Addrs()
			if err != nil {
				return errors.New("reverse host inventory incomplete")
			}
			for _, item := range items {
				local, network, err := net.ParseCIDR(item.String())
				if err == nil && local.To4() != nil && network.Contains(net.ParseIP(ip.Networks[0].IP)) {
					addresses = append(addresses, local.String())
				}
			}
		}
		if len(addresses) == 0 || len(addresses) > 32 {
			return errors.New("no correlated host interface for reverse probe")
		}
		data, err := json.Marshal(struct {
			Addresses []string `json:"addresses"`
			Port      int      `json:"port"`
		}{addresses, reverseSocket.Addr().(*net.TCPAddr).Port})
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(h.input, "host.json"), data, 0o600); err != nil {
			return errors.New("publish reverse endpoint")
		}
		reverseRaw = func(ctx context.Context) (net.Conn, error) {
			deadline := time.Now().Add(5 * time.Second)
			if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
				deadline = bound
			}
			_ = reverseSocket.SetDeadline(deadline)
			for {
				conn, err := reverseSocket.Accept()
				if err != nil {
					return nil, err
				}
				if conn.RemoteAddr().(*net.TCPAddr).IP.Equal(net.ParseIP(ip.Networks[0].IP)) {
					result.TCP = true
					return conn, nil
				}
				_ = conn.Close()
			}
		}
	}
	if !*reverse {
		if raw, err := net.DialTimeout("tcp4", address, 3*time.Second); err == nil {
			result.TCP = true
			_ = raw.Close()
		}
	}
	negative, cancel := context.WithTimeout(ctx, 5*time.Second)
	var conn net.Conn
	if *reverse {
		conn, err = secureDial(report, tls.Certificate{}, reverseRaw)(negative)
	} else {
		conn, err = (&tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}}).DialContext(negative, "tcp4", address) // #nosec G402 -- Negative control sends no application data or credentials.
	}
	if err != nil {
		result.UnauthenticatedRefused = result.TCP
	} else {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = conn.Write([]byte{0})
		var value [1]byte
		_, readErr := conn.Read(value[:])
		result.UnauthenticatedRefused = err != nil || readErr != nil
		_ = conn.Close()
	}
	cancel()
	var response boundedBuffer
	dial := tcpDial(ip.Networks[0].IP, report, client)
	if *reverse {
		dial = secureDial(report, client, reverseRaw)
	}
	if conn, err := dial(ctx); err != nil {
		result.AgentError = "tls-dial"
		result.DialError = "other"
		var networkErr net.Error
		if errors.As(err, &networkErr) && networkErr.Timeout() {
			result.DialError = "timeout"
		}
		var native syscall.Errno
		if errors.As(err, &native) {
			result.DialError = fmt.Sprintf("native-%d", native)
		}
		if err.Error() == "sandbox server pin refused" {
			result.DialError = "server-pin"
		}
		return errors.New("sandbox authenticated TLS unavailable")
	} else {
		result.TLS = true
		_ = conn.Close()
	}
	if err := guestagent.Run(ctx, dial, []string{guestBinary, "facts"}, nil, &response); err != nil {
		result.AgentError = "facts"
		return errors.New("sandbox framed agent facts failed")
	}
	var observed sessionFacts
	if decodeBounded(bytes.NewReader(response.data), &observed) != nil || !observed.valid() {
		result.AgentError = "session"
		return errors.New("sandbox framed session proof failed")
	}
	result.Agent = true
	response = boundedBuffer{}
	if err := guestagent.Run(ctx, dial, []string{guestBinary, "smoke"}, strings.NewReader("bivouac-sandbox-stdin-probe"), &response); err != nil {
		result.AgentError = "smoke"
		var exit *guestagent.ExitError
		if errors.As(err, &exit) {
			result.AgentExit = exit.Code
		}
		return errors.New("sandbox authenticated agent smoke failed")
	}
	var smoke smokeFacts
	if decodeBounded(bytes.NewReader(response.data), &smoke) != nil {
		return errors.New("sandbox smoke response invalid")
	}
	result.Agent = true
	result.Smoke = &smoke
	if !smoke.valid(true) || !smoke.Input {
		return errors.New("sandbox framed smoke predicates failed")
	}
	return nil
}
