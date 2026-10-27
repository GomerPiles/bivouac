package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func waitSummary(t *testing.T, s *Service, expected Summary) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for s.Snapshot() != expected {
		if time.Now().After(deadline) {
			t.Fatal("unexpected transfer totals", s.Snapshot(), expected)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCacheSummaryCountsActualRangesAndIgnoresHead(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"immutable"`)
		w.Header().Set("Content-Length", "7")
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, "payload")
		}
	}))
	defer backend.Close()
	s, b, client := testService(t, backend)
	local := makeLease(t, b, client, backend.URL+"/archive?sig=synthetic-private")
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodGet} {
		req, _ := http.NewRequest(method, local, nil)
		if method == http.MethodGet && s.Snapshot().Archives.Misses == 1 {
			req.Header.Set("Range", "bytes=1-3")
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if method == http.MethodGet && s.Snapshot().Archives.Misses == 0 {
			waitSummary(t, s, Summary{Archives: Counters{Misses: 1, MissBytes: 7}})
		}
	}
	want := Summary{Archives: Counters{Hits: 1, HitBytes: 3, Misses: 1, MissBytes: 7}}
	waitSummary(t, s, want)
	conditional, _ := http.NewRequest(http.MethodGet, local, nil)
	conditional.Header.Set("If-None-Match", `"immutable"`)
	response, err := client.Do(conditional)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotModified {
		t.Fatal("conditional cache read changed")
	}
	want.Archives.Hits++
	waitSummary(t, s, want)
	request, _ := http.NewRequest(http.MethodGet, b.URL+"/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+b.Token)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var own Summary
	err = json.NewDecoder(response.Body).Decode(&own)
	_ = response.Body.Close()
	if err != nil || own != want {
		t.Fatal("authenticated numeric summary differs", own, err)
	}
	otherData, err := s.Issue("other-guest", GrantCapabilities{ReleaseProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	var other Bootstrap
	if err := json.Unmarshal(otherData, &other); err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+other.Token)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	own = Summary{}
	err = json.NewDecoder(response.Body).Decode(&own)
	_ = response.Body.Close()
	if err != nil || own != (Summary{}) {
		t.Fatal("other guest received transfer totals", own, err)
	}
	s.Revoke("guest")
	request.Header.Set("Authorization", "Bearer "+b.Token)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("revoked summary remained accessible")
	}
}

func TestProxySummarySeparatesHitsMissesAndBypasses(t *testing.T) {
	s, client, _ := proxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"immutable"`)
		w.Header().Set("Content-Length", "7")
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, "payload")
		}
	}))
	for _, authorization := range []bool{false, false, true} {
		req, _ := http.NewRequest(http.MethodGet, "https://github.com/example/tool/releases/download/v1/tool.tar.xz", nil)
		if authorization {
			req.Header.Set("Authorization", "Bearer synthetic-origin-credential")
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	waitSummary(t, s, Summary{Releases: Counters{Hits: 1, HitBytes: 7, Misses: 1, MissBytes: 7, Bypasses: 1, BypassBytes: 7}})
}

type failingBodyWriter struct{ header http.Header }

func (w *failingBodyWriter) Header() http.Header          { return w.header }
func (*failingBodyWriter) WriteHeader(int)                {}
func (*failingBodyWriter) Write(data []byte) (int, error) { return min(len(data), 3), io.ErrClosedPipe }

func TestPartialTransferAndFailedFillDoNotFabricateBytes(t *testing.T) {
	validBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"immutable"`)
		w.Header().Set("Content-Length", "7")
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, "payload")
		}
	}))
	defer validBackend.Close()
	validService, validBootstrap, validClient := testService(t, validBackend)
	validLocal := makeLease(t, validBootstrap, validClient, validBackend.URL+"/archive?sig=synthetic")
	for range 2 {
		req, _ := http.NewRequest(http.MethodGet, validLocal, nil)
		validService.ServeHTTP(&failingBodyWriter{header: http.Header{}}, req)
	}
	waitSummary(t, validService, Summary{Archives: Counters{Hits: 1, HitBytes: 3, Misses: 1, MissBytes: 3, Failures: 2}})
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"immutable"`)
		w.Header().Set("Content-Length", "7")
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, "short")
		}
	}))
	defer backend.Close()
	s, b, client := testService(t, backend)
	local := makeLease(t, b, client, backend.URL+"/archive?sig=synthetic")
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(local)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	// The short body streamed before the fill failed: the guest has exactly the
	// bytes it received, counted as a failed miss.
	if response.StatusCode != http.StatusOK || string(got) != "short" {
		t.Fatal("streamed fill failure misreported", response.StatusCode, string(got))
	}
	waitSummary(t, s, Summary{Archives: Counters{Misses: 1, MissBytes: 5, Failures: 1}})
}

func TestGuestCacheSummaryNumericPrivateBoundedAndOptional(t *testing.T) {
	backend := httptest.NewTLSServer(http.NotFoundHandler())
	defer backend.Close()
	s, b, _ := testService(t, backend)
	s.recordTransfer(b.Token, false, cacheHit, 123, false)
	directory := t.TempDir()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, guestConfigFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	PrintGuestSummary(context.Background(), &out, directory)
	if !strings.Contains(out.String(), "hits=1 (123 bytes)") || strings.Contains(out.String(), "uploads") || strings.Contains(out.String(), b.Token) || strings.Contains(out.String(), directory) || strings.Count(out.String(), "\n") != 1 {
		t.Fatal(out.String())
	}
	out.Reset()
	PrintGuestSummary(context.Background(), &out, t.TempDir())
	if out.Len() != 0 {
		t.Fatal("disabled cache added noise", out.String())
	}
	if err := os.WriteFile(filepath.Join(directory, guestConfigFile), []byte(strings.Repeat("x", 32<<10+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	PrintGuestSummary(context.Background(), &out, directory)
	if out.String() != "[bivouac cache] summary unavailable\n" {
		t.Fatal(out.String())
	}
}

// macOS guests use a direct host IP, rather than the Windows SSH endpoint at
// 127.0.0.1. IPv6 loopback exercises that path without exposing a LAN listener.
func TestGuestCacheSummaryAcceptsOtherLiteralEndpoint(t *testing.T) {
	s, err := Start(t.TempDir(), "[::1]:0", "::1", 1<<20, 1<<19, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	defer s.Close()
	data, err := s.Issue("vz-fixture", GrantCapabilities{ReleaseProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	var b Bootstrap
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	s.recordTransfer(b.Token, false, cacheMiss, 7, false)
	s.recordTransfer(b.Token, false, cacheHit, 7, false)
	s.recordTransfer(b.Token, true, cacheHit, 13, false)
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, guestConfigFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	PrintGuestSummary(context.Background(), &out, directory)
	if !strings.Contains(out.String(), "archives: hits=1 (7 bytes) misses=1 (7 bytes)") || !strings.Contains(out.String(), "release proxy: hits=1 (13 bytes)") || strings.Contains(out.String(), b.Token) {
		t.Fatal("direct host endpoint did not report both cache kinds", out.String())
	}
}

// Upload counters appear only for a guest whose saves the host may store.
func TestGuestCacheSummaryReportsUploadsWhenStored(t *testing.T) {
	backend := httptest.NewTLSServer(http.NotFoundHandler())
	defer backend.Close()
	s, _, _ := testService(t, backend)
	s.EnableUploadStore()
	data, err := s.Issue("stored", GrantCapabilities{ReleaseProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	var b Bootstrap
	if err = json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	s.addUpload(b.Token, func(c *UploadCounters) { c.Relayed, c.Stored, c.StoredBytes, c.Fallbacks = 2, 1, 9, 1 })
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, guestConfigFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	PrintGuestSummary(context.Background(), &out, directory)
	if !strings.HasSuffix(out.String(), "; uploads: relayed=2 stored=1 (9 bytes) skipped=0 fallbacks=1\n") {
		t.Fatal(out.String())
	}
}
