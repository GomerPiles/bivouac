package cache

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/engine"
)

func agentCacheFixture(t *testing.T) (net.Conn, <-chan struct{}) {
	t.Helper()
	host, guest := net.Pipe()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	t.Cleanup(func() { _ = host.Close(); _ = guest.Close(); _ = listener.Close() })
	go func() {
		defer close(ended)
		defer func() { _ = guest.Close() }()
		if json.NewEncoder(guest).Encode(struct {
			Port int `json:"port"`
		}{listener.Addr().(*net.TCPAddr).Port}) != nil {
			return
		}
		_ = engine.Listen(t.Context(), guest, listener, 64)
	}()
	return host, ended
}
func TestAgentCacheTLSRelayAndRevocation(t *testing.T) {
	for _, mode := range []string{"revoke", "shutdown", "transport-loss"} {
		t.Run(mode, func(t *testing.T) {
			backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "15")
				w.Header().Set("ETag", `"fixture"`)
				if r.Method != http.MethodHead {
					_, _ = w.Write([]byte("fixture archive"))
				}
			}))
			defer backend.Close()
			service, _, _ := testService(t, backend)
			service.EnableReleaseProxy()
			stream, ended := agentCacheFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			data, err := service.AttachAgent(ctx, "agent-guest", func(context.Context) (net.Conn, error) { return stream, nil })
			if err != nil {
				t.Fatal(err)
			}
			defer clear(data)
			cancel() // Setup cancellation must not close a successful attachment.
			var bootstrap Bootstrap
			if json.Unmarshal(data, &bootstrap) != nil {
				t.Fatal("bootstrap unavailable")
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(bootstrap.CA)) {
				t.Fatal("CA unavailable")
			}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, Timeout: 5 * time.Second}
			defer client.CloseIdleConnections()
			response, err := client.Get(bootstrap.URL + "/ca.crl")
			if err != nil {
				t.Fatal("TLS relay unavailable", err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatal("PKI handler unavailable")
			}
			lease := makeLease(t, bootstrap, client, backend.URL+"/archive")
			request, err := http.NewRequest(http.MethodGet, lease, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+bootstrap.Token)
			response, err = client.Do(request)
			if err != nil {
				t.Fatal("cache request unavailable", err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, []byte("fixture archive")) {
				t.Fatal("cache bytes differ")
			}
			switch mode {
			case "revoke":
				service.Revoke("agent-guest")
			case "shutdown":
				service.Close()
			case "transport-loss":
				_ = stream.Close()
			}
			select {
			case <-ended:
			case <-time.After(5 * time.Second):
				t.Fatal("guest listener survived revocation/loss")
			}
			if response, err := client.Get(bootstrap.URL + "/ca.crl"); err == nil {
				_ = response.Body.Close()
				t.Fatal("lost cache relay remained available")
			}
			if mode == "transport-loss" {
				// The adapter's upstream destination remains independent of the relay.
				response, err := backend.Client().Get(backend.URL + "/archive")
				if err != nil {
					t.Fatal("upstream unavailable after cache loss", err)
				}
				_ = response.Body.Close()
			}
		})
	}
}
func TestAgentCacheRejectsPreludeAndCancelsStalledAttachment(t *testing.T) {
	for _, prelude := range []string{"{}\n", "{\"port\":0}\n", "{\"port\":65536}\n", string(bytes.Repeat([]byte("x"), 64)), "stall"} {
		t.Run(prelude, func(t *testing.T) {
			service, err := Start(t.TempDir(), "127.0.0.1:0", "127.0.0.1", 1<<20, 1<<19, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			host, guest := net.Pipe()
			defer func() { _ = guest.Close() }()
			ended := make(chan struct{})
			go func() {
				defer close(ended)
				if prelude != "stall" {
					_, _ = io.WriteString(guest, prelude)
				}
				_, _ = io.Copy(io.Discard, guest)
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			if _, err := service.AttachAgent(ctx, "fixture", func(context.Context) (net.Conn, error) { return host, nil }); err == nil {
				t.Fatal("invalid prelude accepted")
			}
			select {
			case <-ended:
			case <-time.After(time.Second):
				t.Fatal("failed attachment leaked stream")
			}
		})
	}
}
func TestAgentCacheRefusesCanceledAndUnavailableOpen(t *testing.T) {
	service, err := Start(t.TempDir(), "127.0.0.1:0", "127.0.0.1", 1<<20, 1<<19, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if _, err := service.AttachAgent(t.Context(), "fixture", func(context.Context) (net.Conn, error) { return nil, errors.New("private open failure") }); err == nil || err.Error() != "guest cache agent unavailable" {
		t.Fatal("open failure escaped fixed error")
	}
}
