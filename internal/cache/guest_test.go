package cache

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cachelink"
)

func TestGuestCachePrivateSetupEnvironmentAndRemoval(t *testing.T) {
	backend := httptest.NewTLSServer(http.NotFoundHandler())
	defer backend.Close()
	_, b, _ := testService(t, backend)
	dir := filepath.Join(t.TempDir(), "guest directory")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	// No release proxy: this test never touches the host trust store.
	if err = PrepareGuest(context.Background(), dir, data); err != nil {
		t.Fatal(err)
	}
	env, cleanup, err := GuestEnvironment(dir)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	merged := MergeEnvironment([]string{"Node_Options=stale", "HTTPS_PROXY=original", "KEEP=value"}, env)
	options := 0
	for _, value := range merged {
		if strings.Contains(value, b.Token) || strings.Contains(value, "CERTIFICATE") {
			t.Fatal("capability or trust contents escaped into environment")
		}
		if strings.HasPrefix(value, "NODE_OPTIONS=") {
			options++
			if !strings.Contains(value, `--require="`+filepath.ToSlash(filepath.Join(dir, "cache-preload.cjs"))+`"`) {
				t.Fatal("preload path not quoted")
			}
		}
	}
	if options != 1 {
		t.Fatal("case-insensitive environment replacement failed")
	}
	if err = RemoveGuest(dir); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("private cache configuration retained")
	}
	env, cleanup, err = GuestEnvironment(dir)
	if err != nil || len(env) != 0 {
		t.Fatal("missing adapter did not restore normal downloads")
	}
	cleanup()
}

func TestGuestEnvironmentLoadsNodePreloadWithSpacesAndWindowsPaths(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is required to verify the actual preload environment")
	}
	backend := httptest.NewTLSServer(http.NotFoundHandler())
	defer backend.Close()
	_, b, _ := testService(t, backend)
	dir := filepath.Join(t.TempDir(), "guest directory")
	if err = os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err = PrepareGuest(context.Background(), dir, data); err != nil {
		t.Fatal(err)
	}
	values, cleanup, err := GuestEnvironment(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	// Cold Node startup can consume the former ten-second bound on hosted
	// Windows. This remains an isolated loopback probe with a bounded lifetime.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	program := `const https=require('node:https');const req=https.request(process.argv[1]+'/probe',res=>{res.resume();res.on('end',()=>{if(res.statusCode!==404)process.exitCode=2;});});req.on('error',()=>process.exitCode=3);req.end();`
	cmd := exec.CommandContext(ctx, node, "-e", program, b.URL)
	cmd.Env = MergeEnvironment(os.Environ(), values)
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			t.Fatal("Node cache preload probe exceeded its test deadline")
		}
		t.Fatal("Node did not load the cache preload or trust its endpoint from the actual runner environment")
	}
}

// Exercise the actual shared guest files and runner environment against a real
// endpoint transport. Only the clone trust installer is substituted; this test
// never installs a certificate into the host OS.
func TestPreparedGuestEnvironmentEndpointAndOutageFallback(t *testing.T) {
	service, _, _ := proxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("cache capability reached upstream")
		}
		w.Header().Set("ETag", `"guest-env"`)
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "payload")
		}
	}))
	bootstrap, _, _ := endpointFixture(t, service)
	data, err := json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	dir := t.TempDir()
	trusts := 0
	err = prepareGuest(context.Background(), dir, data, func(_ context.Context, caFile string) ([]byte, error) {
		trusts++
		ca, err := os.ReadFile(caFile)
		if err != nil || string(ca) != bootstrap.CA {
			t.Fatal("wrong clone trust material", err)
		}
		return ca, nil
	})
	if err != nil || trusts != 1 {
		t.Fatal("release trust step not selected", err)
	}
	values, closeGuest, err := GuestEnvironment(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeGuest()
	proxyURL, bypass := "", ""
	for _, value := range values {
		if strings.HasPrefix(value, "HTTP_PROXY=") {
			proxyURL = strings.TrimPrefix(value, "HTTP_PROXY=")
		}
		if strings.HasPrefix(value, "NO_PROXY=") {
			bypass = strings.TrimPrefix(value, "NO_PROXY=")
		}
		if strings.Contains(value, bootstrap.Token) {
			t.Fatal("capability in environment")
		}
	}
	if !strings.Contains(bypass, cachelink.Address) {
		t.Fatal("fixed virtual CRL endpoint lacks proxy bypass")
	}
	endpoint, err := url.Parse(proxyURL)
	if err != nil || endpoint.Host == "" {
		t.Fatal("runner proxy environment missing")
	}
	roots := x509.NewCertPool()
	bundle, err := os.ReadFile(filepath.Join(dir, "cache-roots.pem"))
	if err != nil || !roots.AppendCertsFromPEM(bundle) {
		t.Fatal("runner trust bundle unavailable", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(endpoint), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	for range 2 {
		response, err := client.Get("https://github.com/example/deps/releases/download/v1/asset")
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(payload) != "payload" {
			t.Fatal("runner environment did not use endpoint cache", err)
		}
	}
	if count, _, _ := service.store.Stats(); count != 1 {
		t.Fatal("release was not cached")
	}
	service.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "" {
			t.Error("cache credential leaked during outage fallback")
		}
		_, _ = io.WriteString(w, "direct")
	}))
	defer upstream.Close()
	response, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal("outage blocked direct download", err)
	}
	payload, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(payload) != "direct" {
		t.Fatal("outage fallback changed bytes", err)
	}
	closeGuest()
	if err := RemoveGuest(dir); err != nil {
		t.Fatal(err)
	}
	values, closeGuest, err = GuestEnvironment(dir)
	if err != nil || len(values) != 0 {
		t.Fatal("removal retained runner environment", err)
	}
	closeGuest()
}
