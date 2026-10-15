package cache

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testService(t *testing.T, backend *httptest.Server) (*Service, Bootstrap, *http.Client) {
	t.Helper()
	s, err := Start(t.TempDir(), "127.0.0.1:0", "127.0.0.1", 1<<20, 1<<19, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.client = backend.Client()
	s.validate = func(u *url.URL) bool { return u.Host == strings.TrimPrefix(backend.URL, "https://") }
	data, err := s.Issue("guest")
	if err != nil {
		t.Fatal(err)
	}
	var b Bootstrap
	if err = json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(b.CA))
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, Timeout: time.Minute}
	return s, b, client
}

func makeLease(t *testing.T, b Bootstrap, c *http.Client, source string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"url": source})
	req, _ := http.NewRequest(http.MethodPost, b.URL+"/lease", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+b.Token)
	r, e := c.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = r.Body.Close() }()
	if r.StatusCode != 200 {
		t.Fatalf("lease status %d", r.StatusCode)
	}
	var body struct {
		URL string `json:"url"`
	}
	if e = json.NewDecoder(r.Body).Decode(&body); e != nil {
		t.Fatal(e)
	}
	return body.URL
}

func TestArchiveAuthorizationWarmRangesAndRevocation(t *testing.T) {
	var gets, heads atomic.Int32
	var allowed atomic.Bool
	allowed.Store(true)
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed.Load() {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("ETag", `"immutable"`)
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodHead {
			heads.Add(1)
			return
		}
		gets.Add(1)
		_, _ = io.WriteString(w, "payload")
	}))
	defer backend.Close()
	s, b, client := testService(t, backend)
	source := backend.URL + "/archive?sig=signed-capability"
	for range 2 {
		local := makeLease(t, b, client, source)
		head, e := client.Head(local)
		if e != nil {
			t.Fatal(e)
		}
		_ = head.Body.Close()
		if count, _, _ := s.store.Stats(); head.StatusCode != 200 || head.ContentLength != 7 || head.Header.Get("ETag") != `"immutable"` || count == 0 && gets.Load() != 0 {
			t.Fatal("HEAD filled the cache or lost lease metadata")
		}
		response, e := client.Get(local)
		if e != nil {
			t.Fatal(e)
		}
		data, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if string(data) != "payload" {
			t.Fatal("archive changed")
		}
	}
	if gets.Load() != 1 || heads.Load() != 2 {
		t.Fatalf("authorization bypass or duplicate download: %d %d", gets.Load(), heads.Load())
	}
	local := makeLease(t, b, client, source)
	req, _ := http.NewRequest(http.MethodGet, local, nil)
	req.Header.Set("Range", "bytes=1-3")
	response, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 206 || string(data) != "ayl" {
		t.Fatal("range download failed")
	}
	payload, _ := json.Marshal(map[string]string{"url": source, "sha256": strings.Repeat("0", 64)})
	req, _ = http.NewRequest(http.MethodPost, b.URL+"/lease", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+b.Token)
	response, e = client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatal("lease accepted an unknown field")
	}
	allowed.Store(false)
	payload, _ = json.Marshal(map[string]string{"url": source})
	req, _ = http.NewRequest(http.MethodPost, b.URL+"/lease", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+b.Token)
	response, e = client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	_ = response.Body.Close()
	if response.StatusCode == 200 {
		t.Fatal("cached bytes bypassed upstream denial")
	}
	s.Revoke("guest")
	response, e = client.Get(local)
	if e != nil {
		t.Fatal(e)
	}
	_ = response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("revoked lease served")
	}
}

func TestURLPolicy(t *testing.T) {
	for _, source := range []string{"http://valid.blob.core.windows.net/x?sig=y", "https://user@valid.blob.core.windows.net/x?sig=y", "https://valid.blob.core.windows.net:443/x?sig=y", "https://valid.blob.core.windows.net.evil/x?sig=y", "https://127.0.0.1/x?sig=y", "https://valid.blob.core.windows.net/x"} {
		u, _ := url.Parse(source)
		if allowedURL(u) {
			t.Fatalf("accepted unsafe URL %s", source)
		}
	}
	u, _ := url.Parse("https://valid.blob.core.windows.net/x?sig=y")
	if !allowedURL(u) {
		t.Fatal("valid archive rejected")
	}
}

func TestGuestRootNameConstraints(t *testing.T) {
	s, err := Start(t.TempDir(), "127.0.0.1:0", "127.0.0.1", 1<<20, 1<<19, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.proxy.ca)
	verify := func(name string, leaf *x509.Certificate) error {
		_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name})
		return err
	}
	for _, host := range []string{"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "evil.example"} {
		pair, err := s.proxy.leaf(host, s.url)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(pair.Certificate[0])
		if err = verify(host, leaf); (err == nil) != (host != "evil.example") {
			t.Fatalf("name constraints mishandled %s: %v", host, err)
		}
	}
	if err = verify("127.0.0.1", s.proxy.ca); err != nil {
		t.Fatal("service address rejected", err)
	}
	other := *s.proxy.ca
	other.IPAddresses = []net.IP{net.ParseIP("10.0.0.1")}
	other.PermittedDNSDomains, other.PermittedIPRanges, other.IsCA = nil, nil, false
	der, err := x509.CreateCertificate(rand.Reader, &other, s.proxy.ca, s.proxy.signer.Public(), s.proxy.signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	if verify("10.0.0.1", leaf) == nil {
		t.Fatal("root vouched for an address outside the service")
	}
}
