//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"net"
	"strings"
	"testing"
	"time"
)

func TestMutualTLSRequiresBothPerLaunchPins(t *testing.T) {
	client, _, err := certificate(true)
	if err != nil {
		t.Fatal(err)
	}
	server, _, err := certificate(false)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := certificate(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		client    tls.Certificate
		badServer bool
		want      bool
	}{{"matching", client, false, true}, {"other client", other, false, false}, {"no client", tls.Certificate{}, false, false}, {"other server pin", client, true, false}} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := tls.Listen("tcp4", "127.0.0.1:0", serverTLS(client.Certificate[0], server))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			done := make(chan bool, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- false
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				secured := conn.(*tls.Conn)
				if secured.Handshake() != nil {
					done <- false
					return
				}
				_, err = secured.Write([]byte{42})
				done <- err == nil
			}()
			fingerprint := sha256.Sum256(server.Certificate[0])
			if test.badServer {
				fingerprint[0] ^= 1
			}
			report := tcpReport{Port: listener.Addr().(*net.TCPAddr).Port, Fingerprint: hex.EncodeToString(fingerprint[:])}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := tcpDial("127.0.0.1", report, test.client)(ctx)
			accepted := false
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var value [1]byte
				_, err = conn.Read(value[:])
				accepted = err == nil && value[0] == 42
				_ = conn.Close()
			}
			<-done
			if accepted != test.want {
				t.Fatalf("authentication accepted=%v", accepted)
			}
		})
	}
}

func TestSandboxSessionDoesNotRequireAConsole(t *testing.T) {
	f := sessionFacts{Session: 1, Console: ^uint32(0), User: true, Elevated: true, Active: true, Desktop: true}
	if !f.valid() {
		t.Fatal("active Sandbox RDP session refused")
	}
	for _, change := range []func(*sessionFacts){func(f *sessionFacts) { f.Session = 0 }, func(f *sessionFacts) { f.User = false }, func(f *sessionFacts) { f.Elevated = false }, func(f *sessionFacts) { f.Active = false }, func(f *sessionFacts) { f.Desktop = false }} {
		bad := f
		change(&bad)
		if bad.valid() {
			t.Fatal("invalid session accepted")
		}
	}
}

func TestSandboxConfigDisablesDevicesAndEscapesPaths(t *testing.T) {
	data, err := xml.Marshal(newConfig(`C:\lab & inputs`, `C:\lab <output>`, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<Networking>Disable</Networking>", "<vGPU>Disable</vGPU>", "<ClipboardRedirection>Disable</ClipboardRedirection>", "<AudioInput>Disable</AudioInput>", "<ReadOnly>true</ReadOnly>", "&amp;", "&lt;"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing config predicate %s", want)
		}
	}
}
