package cache

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func proxyFixture(t *testing.T, handler http.Handler) (*Service, *http.Client, Bootstrap) {
	t.Helper()
	backend := httptest.NewTLSServer(handler)
	t.Cleanup(backend.Close)
	service, bootstrap, _ := testService(t, backend)
	transport := backend.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com" // httptest's fixture SAN.
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
	}
	transport.Proxy = nil
	service.client = &http.Client{Transport: transport, Timeout: time.Minute}
	service.EnableReleaseProxy()
	bootstrap.CA += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw}))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(bootstrap.CA))
	endpoint, _ := url.Parse(bootstrap.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(endpoint), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ProxyConnectHeader: http.Header{"Proxy-Authorization": {"Bearer " + bootstrap.Token}}}, Timeout: time.Minute}
	t.Cleanup(client.CloseIdleConnections)
	bootstrap.ReleaseProxy = true
	return service, client, bootstrap
}

func TestReleaseProxyColdWarmReplacementAndAuthorization(t *testing.T) {
	var gets, heads atomic.Int32
	var version atomic.Int32
	var denied atomic.Bool
	service, client, _ := proxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy capability reached upstream")
		}
		if denied.Load() {
			w.WriteHeader(403)
			return
		}
		etag := `"first"`
		if version.Load() != 0 {
			etag = `"next"`
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", "7")
		w.Header().Set("Content-Disposition", `attachment; filename="arbitrary.tar.xz"`)
		if r.Method == http.MethodHead {
			heads.Add(1)
			return
		}
		gets.Add(1)
		_, _ = io.WriteString(w, "payload")
	}))
	source := "https://github.com/example/arbitrary/releases/download/v1/arbitrary.tar.xz"
	read := func(expected int, authorization bool) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, source, nil)
		if authorization {
			req.Header.Set("Authorization", "Bearer origin-credential")
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		data, _ := io.ReadAll(response.Body)
		if response.StatusCode != expected || expected == 200 && string(data) != "payload" {
			t.Fatalf("unexpected response %d %q", response.StatusCode, data)
		}
	}
	read(200, false)
	read(200, false)
	if gets.Load() != 1 || heads.Load() != 2 {
		t.Fatalf("cold/warm counts %d/%d", gets.Load(), heads.Load())
	}
	version.Store(1)
	read(200, false)
	if gets.Load() != 2 {
		t.Fatal("replacement served stale bytes")
	}
	read(200, true)
	if gets.Load() != 3 || heads.Load() != 3 {
		t.Fatal("authenticated download was cached")
	}
	denied.Store(true)
	read(403, false)
	if gets.Load() != 3 {
		t.Fatal("permission denial exposed cached bytes")
	}
	count, _, _ := service.store.Stats()
	if count != 2 {
		t.Fatalf("unexpected object count %d", count)
	}
}

func TestReleaseProxyGuestBridgeAndOpaqueTunnel(t *testing.T) {
	_, _, bootstrap := proxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("guest capability reached origin %s", r.Host)
		}
		w.Header().Set("ETag", `"identity"`)
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "payload")
		}
	}))
	bridge, err := NewGuestProxy(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	local := httptest.NewServer(bridge)
	defer local.Close()
	endpoint, _ := url.Parse(local.URL)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(bootstrap.CA))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(endpoint), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, Timeout: time.Minute}
	defer client.CloseIdleConnections()
	response, err := client.Get("https://github.com/example/deps/releases/download/v1/asset")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(data) != "payload" {
		t.Fatal("guest bridge changed content")
	}
	// The fixture's original example.com certificate survives an opaque tunnel;
	// only that origin identity can satisfy the client's hostname verification.
	response, err = client.Get("https://example.com/asset")
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(data) != "payload" || response.TLS.PeerCertificates[0].Issuer.CommonName == "bivouac guest cache" {
		t.Fatal("opaque tunnel changed origin bytes or identity")
	}
	// Cleartext inside CONNECT and absolute-form https requests are carried by
	// the bridge itself. A non-release origin behind an opaque host tunnel must
	// never receive the guest capability.
	for _, raw := range []string{
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nGET /asset HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"GET https://example.com/asset HTTP/1.1\r\nHost: example.com\r\n\r\n",
	} {
		conn, err := net.Dial("tcp", endpoint.Host)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.WriteString(conn, raw)
		reader := bufio.NewReader(conn)
		if strings.HasPrefix(raw, "CONNECT") {
			if response, err = http.ReadResponse(reader, &http.Request{Method: http.MethodConnect}); err != nil || response.StatusCode != 200 {
				t.Fatalf("CONNECT failed: %v", err)
			}
		}
		response, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatal(err)
		}
		data, _ = io.ReadAll(response.Body)
		_ = response.Body.Close()
		_ = conn.Close()
		if response.StatusCode != 200 || string(data) != "payload" {
			t.Fatalf("bridged origin request failed: %d", response.StatusCode)
		}
	}
}

func TestGuestBridgeUpstreamWhenHostUnavailable(t *testing.T) {
	service, _, bootstrap := proxyFixture(t, http.NotFoundHandler())
	service.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credential leaked on fallback")
		}
		_, _ = io.WriteString(w, "upstream")
	}))
	defer backend.Close()
	bridge, err := NewGuestProxy(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	local := httptest.NewServer(bridge)
	defer local.Close()
	endpoint, _ := url.Parse(local.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(endpoint)}, Timeout: time.Minute}
	defer client.CloseIdleConnections()
	response, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(data) != "upstream" {
		t.Fatal("cache outage blocked upstream")
	}
}

func TestGuestBridgeCleartextConnectUsesVerifiedHTTPS(t *testing.T) {
	_, _, bootstrap := proxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("upstream transport was not TLS")
		}
		w.Header().Set("ETag", `"identity"`)
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "payload")
		}
	}))
	bridge, err := NewGuestProxy(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	local := httptest.NewServer(bridge)
	defer local.Close()
	endpoint, _ := url.Parse(local.URL)
	conn, err := net.Dial("tcp", endpoint.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v", err)
	}
	_, _ = io.WriteString(conn, "GET /example/deps/releases/download/v1/asset HTTP/1.1\r\nHost: github.com\r\n\r\n")
	response, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || string(data) != "payload" {
		t.Fatal("plaintext CONNECT download failed")
	}
}

func TestProxyRevocationAndAuthority(t *testing.T) {
	service, _, b := proxyFixture(t, http.NotFoundHandler())
	endpoint, _ := url.Parse(b.URL)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(b.CA))
	conn, err := tls.Dial("tcp", endpoint.Host, &tls.Config{RootCAs: roots, ServerName: endpoint.Hostname(), MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\nProxy-Authorization: Bearer "+b.Token+"\r\n\r\n")
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT failed %v", err)
	}
	secured := tls.Client(&readerConn{Conn: conn, reader: reader}, &tls.Config{RootCAs: roots, ServerName: "github.com", MinVersion: tls.VersionTLS12})
	if err = secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(secured, "GET /secret HTTP/1.1\r\nHost: private.example\r\n\r\n")
	response, err = http.ReadResponse(bufio.NewReader(secured), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("CONNECT authority escaped")
	}
	service.Revoke("guest")
	_ = secured.SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	if _, err = secured.Read(data[:]); err == nil {
		t.Fatal("revoked tunnel remained open")
	}
}

func TestReleaseRequestPolicy(t *testing.T) {
	for _, source := range []string{"https://github.com/example/deps/releases/download/v1/archive", "https://release-assets.githubusercontent.com/github-production-release-asset/123/456?sig=temporary"} {
		r, _ := http.NewRequest(http.MethodGet, source, nil)
		if !releaseRequest(r) {
			t.Fatal("eligible release rejected")
		}
		for _, header := range []string{"Authorization", "Cookie", "Range", "If-None-Match"} {
			r.Header.Set(header, "value")
			if releaseRequest(r) {
				t.Fatal("unsafe cache admission")
			}
			r.Header.Del(header)
		}
	}
	for _, source := range []string{"https://github.com/example/deps/archive/main.tar.gz", "https://github.com/example/deps/releases/download/v1/archive?private=1", "https://github.com.evil/example/deps/releases/download/v1/archive", "http://github.com/example/deps/releases/download/v1/archive"} {
		r, _ := http.NewRequest(http.MethodGet, source, nil)
		if releaseRequest(r) {
			t.Fatal("unrelated download admitted")
		}
	}
}

func TestReleaseProxyRespectsResponseCachePolicy(t *testing.T) {
	for _, header := range []string{"Cache-Control", "Vary", "Set-Cookie"} {
		t.Run(header, func(t *testing.T) {
			var gets atomic.Int32
			service, client, _ := proxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"identity"`)
				w.Header().Set("Content-Length", "7")
				value := "private, no-store"
				if header == "Vary" {
					value = "Accept"
				}
				if header == "Set-Cookie" {
					value = "session=private"
				}
				w.Header().Set(header, value)
				if r.Method == http.MethodGet {
					gets.Add(1)
					_, _ = io.WriteString(w, "payload")
				}
			}))
			for range 2 {
				response, err := client.Get("https://github.com/example/deps/releases/download/v1/asset")
				if err != nil {
					t.Fatal(err)
				}
				data, _ := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if string(data) != "payload" || response.Header.Get(header) == "" {
					t.Fatal("bypass changed response")
				}
			}
			count, _, _ := service.store.Stats()
			if count != 0 || gets.Load() != 2 {
				t.Fatal("uncacheable response was stored")
			}
		})
	}
}

func TestPublicTransportRejectsHostNetworks(t *testing.T) {
	transport := publicClient().Transport.(*http.Transport)
	for _, address := range []string{"127.0.0.1:443", "192.168.1.1:443", "10.0.0.1:443", "[::1]:443", "169.254.169.254:443", "100.64.0.1:443", "198.18.0.1:443"} {
		conn, err := transport.DialContext(context.Background(), "tcp", address)
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "non-public") {
			t.Fatalf("host network not rejected: %s", address)
		}
	}
}
