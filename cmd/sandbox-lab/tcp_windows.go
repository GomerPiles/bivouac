//go:build windows

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
)

const bootstrapDirectory = `C:\BivouacBootstrap`
const guestLabDirectory = `C:\ProgramData\Bivouac\SandboxLab`

type tcpReport struct {
	ownershipProof
	Port        int          `json:"port"`
	Fingerprint string       `json:"fingerprint"`
	Session     sessionFacts `json:"session"`
}

// Private keys exist only in process memory. Only public certificates and
// fingerprints cross the diagnostic share; neither side logs protocol data.
func certificate(client bool) (tls.Certificate, []byte, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "bivouac-sandbox-lab"}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func readJSON(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.New("lab input unavailable")
	}
	defer func() { _ = f.Close() }()
	return decodeBounded(f, value)
}

func guestOwnership() error {
	var record labRecord
	var request struct {
		ID string `json:"id"`
	}
	if readJSON(filepath.Join(guestLabDirectory, "identity.json"), &record) != nil || !record.valid() || record.Boot == "" || readJSON(filepath.Join(bootstrapDirectory, "request.json"), &request) != nil || !validGUID(request.ID) {
		return errors.New("guest ownership unavailable")
	}
	return writeReport("ownership.json", ownershipProof{Name: record.Name, ID: record.ID, Boot: record.Boot, Request: request.ID})
}

func tcpAgent(ctx context.Context, reverse bool) error {
	self, err := os.Executable()
	if err != nil || !strings.EqualFold(self, guestBinary) || !session().valid() {
		return errors.New("sandbox TCP agent context refused")
	}
	var record labRecord
	if readJSON(filepath.Join(guestLabDirectory, "identity.json"), &record) != nil || !record.valid() || record.Boot == "" {
		return errors.New("sandbox TCP identity refused")
	}
	public, err := os.ReadFile(filepath.Join(bootstrapDirectory, "client.pem"))
	if err != nil || len(public) > 4096 {
		return errors.New("sandbox client pin unavailable")
	}
	block, rest := pem.Decode(public)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("sandbox client pin invalid")
	}
	server, _, err := certificate(false)
	if err != nil {
		return errors.New("sandbox TLS setup failed")
	}
	config := serverTLS(block.Bytes, server)
	var l net.Listener
	if reverse {
		l = newReverseListener(ctx)
	} else {
		// #nosec G102 -- Disposable guest only; mutual TLS is mandatory.
		l, err = net.Listen("tcp4", "0.0.0.0:0")
	}
	if err != nil {
		return errors.New("sandbox TCP listener unavailable")
	}
	defer func() { _ = l.Close() }()
	fingerprint := sha256.Sum256(server.Certificate[0])
	report := tcpReport{ownershipProof: ownershipProof{Name: record.Name, ID: record.ID, Boot: record.Boot}, Port: l.Addr().(*net.TCPAddr).Port, Fingerprint: hex.EncodeToString(fingerprint[:]), Session: session()}
	if err := writeReport("tcp.json", report); err != nil {
		return err
	}
	return guestagent.Serve(ctx, tcpListener{Listener: l, config: config})
}

func serverTLS(clientDER []byte, server tls.Certificate) *tls.Config {
	expected := sha256.Sum256(clientDER)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAnyClientCert, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 || sha256.Sum256(state.PeerCertificates[0].Raw) != expected {
			return errors.New("sandbox client refused")
		}
		return nil
	}}
}

type tcpListener struct {
	net.Listener
	config *tls.Config
}

func (l tcpListener) Accept() (io.ReadWriteCloser, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !session().valid() {
			_ = writeReport("tcp-session-ended.json", session())
			_ = conn.Close()
			return nil, errors.New("sandbox session changed")
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		secured := tls.Server(conn, l.config)
		if err := secured.Handshake(); err != nil {
			_ = writeReport("tcp-rejected.json", struct {
				Rejected bool `json:"rejected"`
			}{true})
			_ = secured.Close()
			continue
		}
		_ = secured.SetDeadline(time.Time{})
		return secured, nil
	}
}

type smokeFacts struct {
	Session         sessionFacts  `json:"session"`
	RunnerVersion   string        `json:"runner_version"`
	ListenerExit    int           `json:"listener_exit"`
	Node            bool          `json:"node"`
	PowerShell      bool          `json:"powershell"`
	HTTPS           bool          `json:"https"`
	DNS             bool          `json:"dns"`
	Input           bool          `json:"input"`
	Protocol        protocolFacts `json:"protocol"`
	NICs            int           `json:"active_nics"`
	NetworkObserved bool          `json:"network_observed"`
}

func (f smokeFacts) valid(online bool) bool {
	base := f.Session.valid() && f.RunnerVersion != "" && f.ListenerExit == 1 && f.Node && f.PowerShell && f.Protocol.Frames && f.Protocol.Input && f.Protocol.Exit && f.NetworkObserved
	if online {
		return base && f.DNS && f.HTTPS && f.NICs > 0
	}
	return base && f.NICs == 0 && !f.DNS && !f.HTTPS
}

func guestSmoke(ctx context.Context, out io.Writer) error {
	facts := smokeFacts{Session: session(), ListenerExit: -1}
	if !facts.Session.valid() {
		return errors.New("sandbox smoke context refused")
	}
	facts.Protocol = protocolSelftest(ctx)
	if adapters, err := net.Interfaces(); err == nil {
		facts.NetworkObserved = true
		for _, adapter := range adapters {
			if adapter.Flags&net.FlagUp != 0 && adapter.Flags&net.FlagLoopback == 0 {
				facts.NICs++
			}
		}
	}
	run := func(binary string, args ...string) ([]byte, int) {
		step, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(step, binary, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Dir = `C:\actions-runner`
		var output boundedBuffer
		cmd.Stdout = &output
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return nil, exit.ExitCode()
			}
			return nil, -1
		}
		return output.data, 0
	}
	version, code := run(`C:\actions-runner\bin\Runner.Listener.exe`, "--version")
	if code == 0 && len(version) < 32 {
		versionText := strings.TrimSpace(string(version))
		if strings.Trim(versionText, "0123456789.") == "" {
			facts.RunnerVersion = versionText
		}
	}
	_, facts.ListenerExit = run(`C:\actions-runner\bin\Runner.Listener.exe`, "run")
	_, code = run(`C:\actions-runner\externals\node24\bin\node.exe`, "-e", "process.exit(0)")
	facts.Node = code == 0
	_, code = run(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "exit 0")
	facts.PowerShell = code == 0
	step, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(step, "api.github.com")
	facts.DNS = err == nil && len(addresses) > 0
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/rate_limit", nil)
	req.Header.Set("User-Agent", "bivouac-sandbox-lab")
	if response, err := client.Do(req); err == nil {
		facts.HTTPS = response.StatusCode == http.StatusOK
		_ = response.Body.Close()
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 65))
	facts.Input = err == nil && string(input) == "bivouac-sandbox-stdin-probe"
	return json.NewEncoder(out).Encode(facts)
}

func tcpDial(address string, report tcpReport, client tls.Certificate) guestagent.Dialer {
	return secureDial(report, client, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(address, fmt.Sprint(report.Port)))
	})
}

func secureDial(report tcpReport, client tls.Certificate, raw guestagent.Dialer) guestagent.Dialer {
	expected, _ := hex.DecodeString(report.Fingerprint)
	return func(ctx context.Context) (net.Conn, error) {
		config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{client}, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error { // #nosec G402 -- Exact per-launch certificate pin replaces DNS/CA verification.
			if len(state.PeerCertificates) != 1 {
				return errors.New("sandbox server refused")
			}
			actual := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
				return errors.New("sandbox server pin refused")
			}
			return nil
		}}
		conn, err := raw(ctx)
		if err != nil {
			return nil, err
		}
		secured := tls.Client(conn, config)
		if err := secured.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return secured, nil
	}
}

type reverseListener struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func newReverseListener(ctx context.Context) *reverseListener {
	ctx, cancel := context.WithCancel(ctx)
	return &reverseListener{ctx: ctx, cancel: cancel}
}
func (l *reverseListener) Addr() net.Addr { return &net.TCPAddr{} }
func (l *reverseListener) Close() error   { l.cancel(); return nil }
func (l *reverseListener) Accept() (net.Conn, error) {
	for {
		var host struct {
			Addresses []string `json:"addresses"`
			Port      int      `json:"port"`
		}
		if readJSON(filepath.Join(bootstrapDirectory, "host.json"), &host) == nil && len(host.Addresses) <= 32 && host.Port > 0 && host.Port <= 65535 {
			for _, address := range host.Addresses {
				ip := net.ParseIP(address)
				if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() {
					continue
				}
				conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(l.ctx, "tcp4", net.JoinHostPort(address, fmt.Sprint(host.Port)))
				if err == nil {
					return conn, nil
				}
			}
		}
		if pause(l.ctx) != nil {
			return nil, l.ctx.Err()
		}
	}
}
