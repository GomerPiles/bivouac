package cache

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A client requiring a fresh positive CRL check must not need a payload slot
// held by its own TLS handshake. All handshakes reach verification together;
// warming TLS/revocation caches cannot hide the capacity dependency.
func TestColdCachedTLSRevocationIndependentOfPayloadCapacity(t *testing.T) {
	if !proxyEnvironmentChild(t) {
		return
	}
	service, _, _ := proxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"revocation-control"`)
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "payload")
		}
	}))
	settings, cacheClient, _ := endpointFixture(t, service)
	proxy, err := NewGuestProxy(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(settings.CA))
	block, _ := pem.Decode([]byte(settings.CA))
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	crlTransport := cacheClient.Transport.(*http.Transport).Clone()
	crlTransport.MaxConnsPerHost = 32
	setRevocationProxyEnvironment(t, proxy, proxyServer.URL)
	crlTransport.Proxy = http.ProxyFromEnvironment
	crlClient := &http.Client{Transport: crlTransport, Timeout: 3 * time.Second}
	defer crlClient.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ready := make(chan struct{})
	var arrived, verified atomic.Int32
	config := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, VerifyConnection: func(state tls.ConnectionState) error {
		if arrived.Add(1) == 32 {
			close(ready)
		}
		select {
		case <-ready:
		case <-ctx.Done():
			return errors.New("cold handshake barrier unavailable")
		}
		locations := state.PeerCertificates[0].CRLDistributionPoints
		if len(locations) != 1 {
			return errors.New("missing revocation endpoint")
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, locations[0], nil)
		response, err := crlClient.Do(request)
		if err != nil {
			return errors.New("positive revocation check unavailable")
		}
		defer func() { _ = response.Body.Close() }()
		data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || len(data) > 16384 || response.StatusCode != 200 {
			return errors.New("invalid revocation response")
		}
		list, err := x509.ParseRevocationList(data)
		if err != nil || list.CheckSignatureFrom(root) != nil || time.Now().Before(list.ThisUpdate) || !time.Now().Before(list.NextUpdate) {
			return errors.New("invalid signed revocation data")
		}
		verified.Add(1)
		return nil
	}}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: config, DisableKeepAlives: true, MaxConnsPerHost: 32}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second}
	var wg sync.WaitGroup
	var failures atomic.Int32
	for range 32 {
		wg.Go(func() {
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://github.com/example/deps/releases/download/v1/control", nil)
			response, err := client.Do(request)
			if err != nil {
				failures.Add(1)
				return
			}
			defer func() { _ = response.Body.Close() }()
			body, err := io.ReadAll(io.LimitReader(response.Body, 8))
			if err != nil || string(body) != "payload" {
				failures.Add(1)
			}
		})
	}
	wg.Wait()
	if failures.Load() != 0 || verified.Load() != 32 {
		t.Fatalf("cold positive-revocation clients: verified=%d failed=%d", verified.Load(), failures.Load())
	}
}

func TestRevocationBypassesPayloadProxyWithSpareCapacity(t *testing.T) {
	if !proxyEnvironmentChild(t) {
		return
	}
	service, _, _ := proxyFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("revocation reached public upstream") }))
	settings, client, _ := endpointFixture(t, service)
	proxy, err := NewGuestProxy(settings)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	server := httptest.NewServer(proxy)
	defer server.Close()
	setRevocationProxyEnvironment(t, proxy, server.URL)
	transport := client.Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get(settings.RevocationURL)
	if err != nil {
		t.Fatal("proxy-aware revocation unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 {
		t.Fatal("revocation recursed through payload proxy")
	}
	if _, err := x509.ParseRevocationList(data); err != nil {
		t.Fatal("signed revocation object unavailable")
	}
	public, _ := url.Parse("https://github.com/example")
	if endpoint, err := http.ProxyFromEnvironment(&http.Request{URL: public}); err != nil || endpoint == nil {
		t.Fatal("revocation bypass also bypassed ordinary public traffic")
	}
}

// net/http caches proxy environment once per process. Use a fresh child so this
// tests the actual standard-library behavior, independent of other tests/env.
func proxyEnvironmentChild(t *testing.T) bool {
	t.Helper()
	if os.Args[len(os.Args)-1] == "revocation-proxy-environment-fixture" {
		return true
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^"+t.Name()+"$", "--", "revocation-proxy-environment-fixture")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("proxy-aware revocation child: %v %s", err, output)
	}
	return false
}
func setRevocationProxyEnvironment(t *testing.T, proxy *GuestProxy, endpoint string) {
	t.Helper()
	t.Setenv("HTTP_PROXY", endpoint)
	t.Setenv("HTTPS_PROXY", endpoint)
	t.Setenv("NO_PROXY", strings.Join(proxy.bypassHosts, ","))
	t.Setenv("REQUEST_METHOD", "")
}
