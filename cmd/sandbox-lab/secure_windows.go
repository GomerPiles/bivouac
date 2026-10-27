//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/hvsock"
	"github.com/GomerPiles/bivouac/internal/sandboxdiscovery"
)

type rejectionReport struct {
	Generation string `json:"generation"`
	Count      uint64 `json:"count"`
}

type secureNativeListener struct {
	net.Listener
	config       *tls.Config
	report       rejectionReport
	validSession func() bool
	rejected     func(rejectionReport) error
}

func (l *secureNativeListener) Accept() (io.ReadWriteCloser, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.validSession == nil || !l.validSession() {
			_ = conn.Close()
			return nil, errors.New("secure native session refused")
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		secured := tls.Server(conn, l.config)
		if secured.Handshake() != nil {
			_ = conn.Close()
			l.report.Count++
			if l.rejected == nil {
				return nil, errors.New("authentication rejection sink unavailable")
			}
			if err := l.rejected(l.report); err != nil {
				return nil, err
			}
			continue
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			_ = conn.Close()
			return nil, errors.New("secure native deadline unavailable")
		}
		return secured, nil
	}
}

func secureNativeAgent(ctx context.Context, listener net.Listener, facts sessionFacts, generation string) error {
	var record labRecord
	if readJSON(filepath.Join(guestLabDirectory, "identity.json"), &record) != nil || !record.valid() || record.Phase != "started" || !validGUID(record.Boot) {
		return errors.New("secure native identity refused")
	}
	public, err := os.ReadFile(filepath.Join(bootstrapDirectory, "client.pem"))
	if err != nil || len(public) > 4096 {
		return errors.New("secure native client pin unavailable")
	}
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("secure native client pin refused")
	}
	server, _, err := certificate(false)
	if err != nil {
		return errors.New("secure native certificate unavailable")
	}
	fingerprint := sha256.Sum256(server.Certificate[0])
	report := agentStartup{sessionFacts: facts, Generation: generation, Identity: &record, Fingerprint: hex.EncodeToString(fingerprint[:])}
	if err := writeReport("agent.json", report); err != nil {
		return err
	}
	return guestagent.Serve(ctx, &secureNativeListener{Listener: listener, config: serverTLS(block.Bytes, server), report: rejectionReport{Generation: generation}, validSession: func() bool { return session().valid() }, rejected: func(r rejectionReport) error { return writeReport("auth-rejected.json", r) }})
}

func (h *labHost) secureReport() (agentStartup, error) {
	var report agentStartup
	err := readJSON(filepath.Join(h.output, "agent.json"), &report)
	if err != nil || !report.valid() || !validGUID(report.Generation) || report.Identity == nil || !sameGuest(*report.Identity, h.record) || len(report.Fingerprint) != 64 || strings.Trim(report.Fingerprint, "0123456789abcdef") != "" {
		return agentStartup{}, errors.New("secure native startup refused")
	}
	return report, nil
}

func sameGuest(observed, expected labRecord) bool {
	return observed.valid() && expected.valid() && observed.Phase == "started" && expected.Phase == "started" && validGUID(expected.Boot) && observed.ID == expected.ID && observed.Name == expected.Name && observed.Boot == expected.Boot
}

// This helper only reads Sandbox-class metadata. Authentication happens in
// the ordinary manager; no private client key or guest RPC enters elevation.
func nativeCandidates(ctx context.Context, out io.Writer) error {
	items, err := sandboxdiscovery.Discover(ctx)
	if err != nil {
		return errors.New("candidate query unavailable")
	}
	candidates := []nativeBinding{}
	for _, item := range items {
		candidates = append(candidates, nativeBinding{NativeID: item.ID, Probe: nativeFacts{HCS: true, Running: true, IDMatches: true, VM: true, Runtime: true, RuntimeID: item.RuntimeID, OwnerHash: sandboxOwnerHash()}})
	}
	return json.NewEncoder(out).Encode(candidates)
}

func nativeRaw(runtimeID string) (guestagent.Dialer, error) {
	if !validGUID(runtimeID) {
		return nil, errors.New("native route refused")
	}
	vm, err := hvsock.ParseGUID(runtimeID)
	if err != nil {
		return nil, errors.New("native route invalid")
	}
	service, _ := hvsock.ParseGUID(serviceID)
	return func(ctx context.Context) (net.Conn, error) {
		step, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return hvsock.Dial(step, hvsock.Addr{VMID: vm, ServiceID: service})
	}, nil
}

func (h *labHost) authenticateCandidates(ctx context.Context, candidates []nativeBinding) (nativeIdentity, error) {
	if len(candidates) < 1 || len(candidates) > 16 {
		return nativeIdentity{}, errors.New("bounded native candidates required")
	}
	report, err := h.secureReport()
	if err != nil {
		return nativeIdentity{}, err
	}
	matched := correlationReport{Candidates: len(candidates)}
	seen := map[string]bool{}
	for _, candidate := range candidates {
		f := &candidate.Probe
		if !validGUID(candidate.NativeID) || seen[candidate.NativeID] || !f.HCS || !f.Running || !f.IDMatches || !f.VM || !f.Runtime || f.OwnerHash != sandboxOwnerHash() {
			return nativeIdentity{}, errors.New("native candidate metadata refused")
		}
		seen[candidate.NativeID] = true
		raw, err := nativeRaw(f.RuntimeID)
		if err != nil {
			return nativeIdentity{}, err
		}
		dial := secureDial(tcpReport{Fingerprint: report.Fingerprint}, h.client, raw)
		step, cancel := context.WithTimeout(ctx, 5*time.Second)
		var buffer boundedBuffer
		err = guestagent.Run(step, dial, []string{guestBinary, "identity"}, nil, &buffer)
		cancel()
		var identity labRecord
		if err != nil || decodeBounded(bytes.NewReader(buffer.data), &identity) != nil || !sameGuest(identity, h.record) {
			continue
		}
		f.Agent, f.Session, f.Identity = true, report.sessionFacts, &identity
		if candidate.matches(h.record) {
			matched.Matches = append(matched.Matches, candidate)
		}
	}
	return matched.binding(h.record)
}

func (h *labHost) authorizationProbes(ctx context.Context, self string, result *labResult) error {
	report, err := h.secureReport()
	if err != nil {
		return err
	}
	raw, err := nativeRaw(h.record.Native.RuntimeID)
	if err != nil {
		return err
	}
	other, _, err := certificate(true)
	if err != nil {
		return errors.New("negative client certificate unavailable")
	}
	for index, client := range []tls.Certificate{{}, other} {
		if err := h.rejectNative(ctx, report, secureDial(tcpReport{Fingerprint: report.Fingerprint}, client, raw)); err != nil {
			return err
		}
		if index == 0 {
			result.MissingClientRefused = true
		} else {
			result.WrongClientRefused = true
		}
	}
	if err := h.rejectNative(ctx, report, raw); err != nil {
		return err
	}
	result.PlaintextRefused = true
	bad := tcpReport{Fingerprint: strings.Repeat("0", 64)}
	step, cancel := context.WithTimeout(ctx, 5*time.Second)
	conn, err := secureDial(bad, h.client, raw)(step)
	cancel()
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || err.Error() != "sandbox server pin refused" {
		return errors.New("wrong server pin not refused")
	}
	result.WrongServerRefused = true
	if err := h.proveNative(ctx); err != nil {
		return err
	}
	var output boundedBuffer
	var before rejectionReport
	if readJSON(filepath.Join(h.output, "auth-rejected.json"), &before) != nil || before.Generation != report.Generation {
		return errors.New("anonymous rejection baseline unavailable")
	}
	command := exec.CommandContext(ctx, self, "anonymous-probe", h.record.Native.RuntimeID, filepath.Join(filepath.Dir(h.input), "record.json"))
	command.Stdout = &output
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if command.Run() != nil {
		return errors.New("anonymous context probe unavailable")
	}
	var anonymous anonymousFacts
	if decodeBounded(bytes.NewReader(output.data), &anonymous) != nil || !anonymous.Anonymous || !anonymous.PrivateReadDenied || !anonymous.ManagerReadDenied {
		return errors.New("anonymous identity or private directory boundary unproven")
	}
	result.Anonymous = &anonymous
	if anonymous.Connected {
		if !anonymous.TLSRefused {
			return errors.New("anonymous TLS refusal unproven")
		}
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		for {
			var after rejectionReport
			if readJSON(filepath.Join(h.output, "auth-rejected.json"), &after) == nil && after.Generation == report.Generation && after.Count >= before.Count+2 {
				break
			}
			if pause(wait) != nil {
				return errors.New("anonymous guest TLS rejection unproven")
			}
		}
	}
	result.Secure = true
	result.TLS = true
	return h.proveNative(ctx)
}

func (h *labHost) rejectNative(ctx context.Context, startup agentStartup, dial guestagent.Dialer) error {
	var before rejectionReport
	_ = readJSON(filepath.Join(h.output, "auth-rejected.json"), &before)
	if before.Generation != startup.Generation {
		before.Count = 0
	}
	step, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	// A fixed identity request is attempted; the server must reject the socket
	// before passing it to the command protocol. A timeout proves nothing.
	err := guestagent.Run(step, dial, []string{guestBinary, "identity"}, nil, io.Discard)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return errors.New("native authentication refusal inconclusive")
	}
	for {
		var after rejectionReport
		if readJSON(filepath.Join(h.output, "auth-rejected.json"), &after) == nil && after.Generation == startup.Generation && after.Count > before.Count {
			break
		}
		if pause(step) != nil {
			return errors.New("guest authentication rejection unproven")
		}
	}
	return h.proveNative(ctx)
}
