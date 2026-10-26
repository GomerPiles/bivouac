package cache

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFullEndpointFallsBackWithoutLeakingCapability(t *testing.T) {
	service, _, _, _, _ := uploadFixture(t)
	service.SetEndpointLimit(32)
	b, client, _ := endpointFixture(t, service)
	endpoint, _ := url.Parse(b.URL)
	config := client.Transport.(*http.Transport).TLSClientConfig
	// Establish and exercise all admitted TLS channels so saturation is observable,
	// without relying on listener timing or attempting to raise the endpoint limit.
	for range 32 {
		conn, err := tls.Dial("tcp", endpoint.Host, config)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		request, _ := http.NewRequest(http.MethodGet, b.URL+"/metrics", nil)
		if err := request.Write(conn); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatal("unauthenticated channel gained cache access")
		}
	}
	var reached atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("cache capability reached direct upstream")
		}
		_, _ = io.WriteString(w, "direct-public-control")
	}))
	defer backend.Close()
	proxy, err := NewGuestProxy(b)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	// The local backend substitutes only the public destination in this fixture.
	// Production direct traffic still passes through the mandatory guest stack.
	address := strings.TrimPrefix(backend.URL, "http://")
	proxy.direct.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	defer transport.CloseIdleConnections()
	direct := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := direct.Get("http://public.example/control")
	if err != nil {
		t.Fatal("full endpoint reset download instead of falling back", err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "direct-public-control" || !reached.Load() {
		t.Fatal("full endpoint did not use direct public fallback")
	}
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("CONNECT fallback leaked capability")
		}
		_, _ = io.WriteString(w, "direct-tls-control")
	}))
	defer secure.Close()
	proxy.directDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(secure.URL, "https://"))
	}
	secureTransport := secure.Client().Transport.(*http.Transport).Clone()
	secureTransport.Proxy = http.ProxyURL(proxyURL)
	defer secureTransport.CloseIdleConnections()
	secureClient := &http.Client{Transport: secureTransport, Timeout: 5 * time.Second}
	tlsResponse, err := secureClient.Get("https://example.com/control")
	if err != nil {
		t.Fatal("full endpoint CONNECT did not fall back", err)
	}
	defer func() { _ = tlsResponse.Body.Close() }()
	data, err = io.ReadAll(tlsResponse.Body)
	if err != nil || string(data) != "direct-tls-control" {
		t.Fatal("full endpoint CONNECT reset TLS download")
	}

}

func TestConcurrentReleaseTunnelsOverEndpoint(t *testing.T) {
	const size = 4 << 20
	service, _, _ := proxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"parallel-control"`)
		w.Header().Set("Content-Length", strconv.Itoa(size))
		if r.Method == http.MethodGet {
			_, _ = io.CopyN(w, cacheZeroReader{}, size)
		}
	}))
	b, client, _ := endpointFixture(t, service)
	endpoint, _ := url.Parse(b.URL)
	transport := client.Transport.(*http.Transport)
	transport.Proxy = http.ProxyURL(endpoint)
	transport.ProxyConnectHeader = http.Header{"Proxy-Authorization": {"Bearer " + b.Token}}
	client.Timeout = 15 * time.Second
	// Warm once before all 16 protocol tunnels read the same cached object concurrently.
	fetch := func() error {
		response, err := client.Get("https://github.com/example/deps/releases/download/v1/parallel")
		if err != nil {
			return err
		}
		defer func() { _ = response.Body.Close() }()
		count, err := io.Copy(io.Discard, response.Body)
		if err != nil {
			return err
		}
		if count != size {
			return errors.New("parallel tunnel lost bytes")
		}
		return nil
	}
	if err := fetch(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 16)
	for range 16 {
		wg.Go(func() { failures <- fetch() })
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestPrivateCacheHopTrustsOnlyBootstrapIssuer(t *testing.T) {
	_, b, _, _, _ := uploadFixture(t)
	proxy, err := NewGuestProxy(b)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	pinned := x509.NewCertPool()
	if !pinned.AppendCertsFromPEM([]byte(b.CA)) {
		t.Fatal("fixture CA invalid")
	}
	if !proxy.tlsConfig.RootCAs.Equal(pinned) {
		t.Fatal("private cache hop included ambient system trust")
	}
	if proxy.proxied.TLSClientConfig.RootCAs.Equal(pinned) {
		t.Fatal("public-origin TLS lost normal trust")
	}
}
