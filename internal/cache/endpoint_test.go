package cache

import (
	"bufio"
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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cachelink"
)

func endpointFixture(t testing.TB, s *Service) (Bootstrap, *http.Client, <-chan struct{}) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	revocation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = l.Close()
		t.Fatal(err)
	}
	host, guest := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runGuestEndpoint(context.Background(), guest, func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", l.Addr().String())
		})
	}()
	data, err := s.AttachEndpoint(context.Background(), "endpoint-guest", host, l, revocation, GrantCapabilities{ReleaseProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	var settings Bootstrap
	if json.Unmarshal(data, &settings) != nil {
		t.Fatal("invalid bootstrap")
	}
	clear(data)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(settings.CA))
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == cachelink.RevocationEndpoint {
			address = revocation.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}, Timeout: 3 * time.Second}
	t.Cleanup(func() {
		client.CloseIdleConnections()
		s.Revoke("endpoint-guest")
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("endpoint survived revocation")
		}
	})
	return settings, client, done
}
func TestEndpointAuthenticationOwnershipAndRevocation(t *testing.T) {
	s, _, _, _, upstream := uploadFixture(t)
	settings, client, done := endpointFixture(t, s)
	otherData, err := s.Issue("other-guest", GrantCapabilities{ReleaseProxy: true})
	var other Bootstrap
	if err != nil || json.Unmarshal(otherData, &other) != nil {
		t.Fatal("other bootstrap failed")
	}
	clear(otherData)
	request, _ := http.NewRequest(http.MethodGet, settings.URL+"/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+other.Token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("endpoint unavailable")
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("other guest admitted")
	}
	payload := []byte("cache endpoint upload and restore")
	relay := createUploadLease(t, settings, client, upstream+"/archive?sig=upload")
	status, _ := relayPut(t, client, settings, relay, map[string]string{"x-ms-blob-type": "BlockBlob"}, payload)
	if status != 201 {
		t.Fatalf("endpoint upload status=%d", status)
	}
	if string(restore(t, settings, client, upstream, "/archive")) != string(payload) {
		t.Fatal("endpoint restore changed bytes")
	}
	otherLease := makeLease(t, other, client, upstream+"/archive?sig=read")
	parsed, _ := url.Parse(otherLease)
	wrongOwner, err := client.Get(settings.URL + parsed.RequestURI())
	if err != nil {
		t.Fatal("owner rejection transport failed")
	}
	_ = wrongOwner.Body.Close()
	if wrongOwner.StatusCode != http.StatusUnauthorized {
		t.Fatal("other guest object capability admitted")
	}
	s.Revoke("endpoint-guest")
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("endpoint control survived revocation")
	}
	if response, err := client.Get(settings.URL + "/metrics"); err == nil {
		_ = response.Body.Close()
		t.Fatal("revoked endpoint admitted connection")
	}
}
func TestEndpointControlHandshakeRejectsGuestText(t *testing.T) {
	for _, response := range []string{"bad!!!", "65536\n", "0\n", "80x\n"} {
		host, guest := net.Pipe()
		go func() { _, _ = io.WriteString(guest, response); _ = guest.Close() }()
		if _, err := readCachePort(host); err == nil {
			t.Fatal("malformed endpoint announcement admitted")
		}
		_ = host.Close()
	}
}

func TestEndpointReleaseProxyColdWarmAndUpstreamRestrictions(t *testing.T) {
	s, _, _ := proxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("capability reached upstream")
		}
		w.Header().Set("ETag", `"fixture"`)
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "payload")
		}
	}))
	b, client, _ := endpointFixture(t, s)
	proxy, _ := url.Parse(b.URL)
	transport := client.Transport.(*http.Transport)
	transport.Proxy = http.ProxyURL(proxy)
	transport.ProxyConnectHeader = http.Header{"Proxy-Authorization": {"Bearer " + b.Token}}
	for range 2 {
		r, err := client.Get("https://github.com/example/deps/releases/download/v1/asset")
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if string(data) != "payload" {
			t.Fatal("release bytes changed")
		}
	}
	if count, _, _ := s.store.Stats(); count != 1 {
		t.Fatal("release did not cache")
	}
	// Replace the fixture's deliberate local backend bypass with real admission.
	transport.CloseIdleConnections()
	s.client.CloseIdleConnections()
	s.client = publicClientAdmission(func(net.IP) bool { return false })
	if r, err := client.Get("https://127.0.0.1/forbidden"); err == nil {
		_ = r.Body.Close()
		t.Fatal("cache became a host network bypass")
	}
}

func TestMacUpstreamAdmissionRequiresPublicNonlocalIPv4(t *testing.T) {
	admit := func(ip net.IP) bool { return !ip.Equal(net.ParseIP("11.22.33.7")) }
	answers := func(values ...string) []net.IPAddr {
		var out []net.IPAddr
		for _, s := range values {
			out = append(out, net.IPAddr{IP: net.ParseIP(s)})
		}
		return out
	}
	ip, err := upstreamIP(answers("2606:4700:4700::1111", "1.1.1.1"), admit)
	if err != nil || !ip.Equal(net.ParseIP("1.1.1.1")) {
		t.Fatal("public dual-stack DNS lacked IPv4 fallback")
	}
	for _, ips := range [][]net.IPAddr{answers("2606:4700:4700::1111"), answers("1.1.1.1", "11.22.33.7"), answers("1.1.1.1", "127.0.0.1"), answers("1.1.1.1", "fd00::1")} {
		if _, err := upstreamIP(ips, admit); err == nil {
			t.Fatal("forbidden DNS answer admitted")
		}
	}
}

func BenchmarkCacheEndpointDownload(b *testing.B) {
	const size = 32 << 20
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("ETag", `"benchmark"`)
		if r.Method == http.MethodGet {
			_, _ = io.CopyN(w, cacheZeroReader{}, size)
		}
	}))
	defer backend.Close()
	service, err := Start(b.TempDir(), "127.0.0.1:0", "127.0.0.1", 256<<20, 64<<20, time.Hour, slog.New(slog.DiscardHandler))
	if err != nil {
		b.Fatal(err)
	}
	defer service.Close()
	service.client = backend.Client()
	service.validate = func(u *url.URL) bool { return u.Host == strings.TrimPrefix(backend.URL, "https://") }
	bootstrap, client, _ := endpointFixture(b, service)
	request, _ := http.NewRequest(http.MethodPost, bootstrap.URL+"/lease", strings.NewReader(`{"url":"`+backend.URL+`/archive?sig=benchmark"}`))
	request.Header.Set("Authorization", "Bearer "+bootstrap.Token)
	response, err := client.Do(request)
	if err != nil {
		b.Fatal(err)
	}
	var lease struct {
		URL string `json:"url"`
	}
	if json.NewDecoder(response.Body).Decode(&lease) != nil {
		b.Fatal("benchmark lease failed")
	}
	_ = response.Body.Close()
	read := func() error {
		r, err := client.Get(lease.URL)
		if err != nil {
			return err
		}
		defer func() { _ = r.Body.Close() }()
		n, err := io.Copy(io.Discard, r.Body)
		if err == nil && n != size {
			return errors.New("benchmark body length differs")
		}
		return err
	}
	if err := read(); err != nil {
		b.Fatal(err)
	}
	for _, parallel := range []int{1, 8, 16, 32} {
		b.Run(strconv.Itoa(parallel), func(b *testing.B) {
			b.SetBytes(int64(parallel * size))
			b.ResetTimer()
			for range b.N {
				var wg sync.WaitGroup
				errs := make(chan error, parallel)
				for range parallel {
					wg.Go(func() { errs <- read() })
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

type cacheZeroReader struct{}

func (cacheZeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }

func TestEndpointExpiredGrantPreservesFallbackResponses(t *testing.T) {
	service, _, _, _, upstream := uploadFixture(t)
	b, client, _ := endpointFixture(t, service)
	relay := createUploadLease(t, b, client, upstream+"/archive?sig=upload")
	service.mu.Lock()
	g := service.grants[b.Token]
	g.expires = time.Now().Add(-time.Second)
	service.grants[b.Token] = g
	service.mu.Unlock()
	status, headers := relayPut(t, client, b, relay, map[string]string{"x-ms-blob-type": "BlockBlob"}, []byte("payload"))
	if status != http.StatusServiceUnavailable || headers.Get("X-Bivouac-Relay") != "unavailable" {
		t.Fatal("expired upload lost retry fallback")
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("capability reached direct backend")
		}
		_, _ = io.WriteString(w, "direct control")
	}))
	defer backend.Close()
	proxy, err := NewGuestProxy(b)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxy.direct.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get("http://public.example/control")
	if err != nil {
		t.Fatal("expired cache did not fall back")
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "direct control" {
		t.Fatal("expired proxy lost public fallback")
	}
}

func TestRevocationCapabilityCannotReachCacheOrProxy(t *testing.T) {
	service, _, _ := proxyFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("revocation capability reached upstream") }))
	_, client, _ := endpointFixture(t, service)
	for _, test := range []struct{ method, path string }{{"GET", "/metrics"}, {"POST", "/lease"}, {"POST", "/upload"}, {"GET", "/object/fixture"}, {"GET", "/ca.crl?extra=1"}, {"POST", "/ca.crl"}, {"CONNECT", "/ca.crl"}} {
		request, _ := http.NewRequest(test.method, "http://"+cachelink.RevocationEndpoint+test.path, nil)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("revocation rejection transport unavailable")
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatal("revocation capability admitted another operation")
		}
	}
	transport := client.Transport.(*http.Transport).Clone()
	endpoint, _ := url.Parse("http://" + cachelink.RevocationEndpoint)
	transport.Proxy = http.ProxyURL(endpoint)
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get("http://public.example/ca.crl")
	if err != nil {
		t.Fatal("absolute-form rejection transport unavailable")
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatal("revocation capability became a forward proxy")
	}
}

func TestRevocationCapabilityLifetimeMatchesPayloadOwner(t *testing.T) {
	service, _, _ := proxyFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	_, client, done := endpointFixture(t, service)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		request, _ := http.NewRequest(method, cachelink.RevocationURL, nil)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("owned revocation capability unavailable")
		}
		data, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || response.ContentLength <= 0 {
			t.Fatal("public revocation object unavailable")
		}
		if method == http.MethodHead && len(data) != 0 {
			t.Fatal("revocation HEAD returned a body")
		}
		if method == http.MethodGet {
			if _, err := x509.ParseRevocationList(data); err != nil {
				t.Fatal("revocation object is not signed PKI data")
			}
		}
	}
	service.Revoke("endpoint-guest")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("payload control survived revocation")
	}
	if response, err := client.Get(cachelink.RevocationURL); err == nil {
		_ = response.Body.Close()
		t.Fatal("revocation capability survived its owner")
	}
}

func TestGuestEndpointRelayHalfClose(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "guest", true: "remote"}[reverse], func(t *testing.T) {
			l, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = l.Close() }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			host, guest := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = runGuestEndpoint(ctx, guest, func(ctx context.Context) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp4", l.Addr().String())
				})
			}()
			defer func() {
				cancel()
				_ = host.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("guest endpoint did not join after cancellation")
				}
			}()
			_ = host.SetReadDeadline(time.Now().Add(3 * time.Second))
			port, err := bufio.NewReader(host).ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			a, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strings.TrimSpace(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = a.Close() }()
			b, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = b.Close() }()
			if reverse {
				a, b = b, a
			}
			_ = a.SetDeadline(time.Now().Add(5 * time.Second))
			_ = b.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(a, "before"); err != nil {
				t.Fatal(err)
			}
			if err := a.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(b)
			if err != nil || string(data) != "before" {
				t.Fatal("first FIN lost data", err)
			}
			if _, err := io.WriteString(b, "after"); err != nil {
				t.Fatal(err)
			}
			if err := b.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			data, err = io.ReadAll(a)
			if err != nil || string(data) != "after" {
				t.Fatal("second direction lost data after FIN", err)
			}
		})
	}
}
