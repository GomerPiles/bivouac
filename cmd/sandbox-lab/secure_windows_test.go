//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecureNativeListenerRejectsBeforeAdmission(t *testing.T) {
	client, _, err := certificate(true)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := certificate(true)
	if err != nil {
		t.Fatal(err)
	}
	server, _, err := certificate(false)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	rejected := make(chan rejectionReport, 4)
	secured := &secureNativeListener{Listener: listener, config: serverTLS(client.Certificate[0], server), report: rejectionReport{Generation: "11111111-2222-4333-8444-555555555555"}, validSession: func() bool { return true }, rejected: func(r rejectionReport) error { rejected <- r; return nil }}
	done := make(chan error, 1)
	go func() {
		conn, err := secured.Accept()
		if err == nil {
			_, err = conn.Write([]byte{42})
			_ = conn.Close()
		}
		done <- err
	}()
	fingerprint := sha256.Sum256(server.Certificate[0])
	report := tcpReport{Fingerprint: hex.EncodeToString(fingerprint[:])}
	raw := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for index, cert := range []tls.Certificate{{}, other} {
		conn, err := secureDial(report, cert, raw)(ctx)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			var value [1]byte
			_, err = conn.Read(value[:])
			_ = conn.Close()
		}
		if err == nil {
			t.Fatal("unauthorized socket admitted")
		}
		select {
		case r := <-rejected:
			if r.Count != uint64(index+1) || r.Generation != secured.report.Generation {
				t.Fatal("rejection proof differs")
			}
		case <-ctx.Done():
			t.Fatal("missing rejection proof")
		}
	}
	plain, err := raw(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = plain.Write([]byte("not TLS"))
	_ = plain.SetReadDeadline(time.Now().Add(time.Second))
	var value [1]byte
	if _, err := plain.Read(value[:]); err == nil {
		t.Fatal("plaintext admitted")
	}
	_ = plain.Close()
	select {
	case r := <-rejected:
		if r.Count != 3 {
			t.Fatal("missing plaintext rejection")
		}
	case <-ctx.Done():
		t.Fatal("missing rejection proof")
	}
	conn, err := secureDial(report, client, raw)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, value[:]); err != nil || value[0] != 42 {
		t.Fatalf("authorized positive control failed: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("listener did not finish")
	}
}

func TestSecureStartupMustMatchOwnedBoot(t *testing.T) {
	record := labRecord{Name: "bivouac-sandbox-11111111-2222-4333-8444-555555555555", ID: "11111111-2222-4333-8444-555555555555", Phase: "started", Boot: "66666666-7777-4888-8999-aaaaaaaaaaaa"}
	valid := agentStartup{sessionFacts: sessionFacts{Session: 1, User: true, Elevated: true, Active: true, Desktop: true}, Generation: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", Identity: &record, Fingerprint: strings.Repeat("a", 64)}
	for _, test := range []struct {
		name   string
		change func(*agentStartup)
	}{
		{"matching", func(*agentStartup) {}},
		{"missing identity", func(r *agentStartup) { r.Identity = nil }},
		{"different boot", func(r *agentStartup) { r.Identity.Boot = r.Generation }},
		{"stopped", func(r *agentStartup) { r.Identity.Phase = "stopped" }},
		{"invalid identity", func(r *agentStartup) { r.Identity.Name = "foreign" }},
		{"missing generation", func(r *agentStartup) { r.Generation = "" }},
		{"inactive session", func(r *agentStartup) { r.Active = false }},
		{"missing fingerprint", func(r *agentStartup) { r.Fingerprint = "" }},
		{"invalid fingerprint", func(r *agentStartup) { r.Fingerprint = strings.Repeat("x", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := valid
			identity := record
			report.Identity = &identity
			test.change(&report)
			host := labHost{record: record, output: t.TempDir()}
			if err := writeJSON(filepath.Join(host.output, "agent.json"), report); err != nil {
				t.Fatal(err)
			}
			_, err := host.secureReport()
			if (err == nil) != (test.name == "matching") {
				t.Fatalf("startup acceptance differs: %v", err)
			}
		})
	}
}
