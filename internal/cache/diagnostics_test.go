package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type failedDelivery struct{ header http.Header }

func (w *failedDelivery) Header() http.Header { return w.header }
func (*failedDelivery) WriteHeader(int)       {}
func (*failedDelivery) Write([]byte) (int, error) {
	return 0, errors.New("synthetic-private-address?sig=synthetic-secret")
}

func TestArchiveDeliveryFailureKeepsOnlySafeCategory(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"immutable"`)
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "payload")
		}
	}))
	defer backend.Close()
	s, b, client := testService(t, backend)
	var logs bytes.Buffer
	s.log = slog.New(slog.NewTextHandler(&logs, nil))
	local := makeLease(t, b, client, backend.URL+"/archive?sig=synthetic")
	s.ServeHTTP(&failedDelivery{header: http.Header{}}, httptest.NewRequest(http.MethodGet, local, nil))
	got := s.Snapshot().Archives
	if got.Misses != 1 || got.MissBytes != 0 || got.Failures != 1 {
		t.Fatal("failed delivery changed accounting", got)
	}
	text := logs.String()
	if !strings.Contains(text, `msg="cache response incomplete"`) || !strings.Contains(text, "reason=response_body") {
		t.Fatal("delivery category missing")
	}
	for _, forbidden := range []string{"synthetic-private-address", "synthetic-secret", local, b.Token} {
		if strings.Contains(text, forbidden) {
			t.Fatal("delivery diagnostic retained private data")
		}
	}
}

func TestStoreDiagnosticsDistinguishEvictionInvalidationAndStartupDiscard(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	dir := t.TempDir()
	s, err := Open(dir, 7, 7, logger)
	if err != nil {
		t.Fatal(err)
	}
	const privateKey = "https://example.blob.core.windows.net/private?sig=synthetic-secret"
	readObject(t, s, privateKey, 7, fill("payload"))
	if err := os.WriteFile(s.path(identity(privateKey)), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if readObject(t, s, privateKey, 7, fill("payload")) {
		t.Fatal("corrupt object served")
	}
	first := "object=" + s.label(privateKey)
	readObject(t, s, "next", 7, fill("another"))
	if got := s.Diagnostics(); got != (StoreDiagnostics{Evictions: 1, EvictedBytes: 7, Invalidations: 1}) {
		t.Fatal("loss categories differ", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "fill-interrupted"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, 7, 7, logger)
	if err != nil {
		t.Fatal(err)
	}
	if s.Diagnostics().StartupDiscardedFiles != 1 {
		t.Fatal("startup discard not recorded")
	}
	// Validation failure, invalidation and the refilled object's later eviction
	// share a label within this session; a new session cannot reproduce it.
	if strings.Count(logs.String(), first) != 3 || strings.Contains(logs.String(), "object="+s.label(privateKey)) {
		t.Fatal("object labels do not correlate one session only", logs.String())
	}
	for _, forbidden := range []string{privateKey, "synthetic-secret", identity(privateKey), identity(privateKey)[:12], dir} {
		if strings.Contains(logs.String(), forbidden) {
			t.Fatal("store diagnostic exposed an identifier")
		}
	}
	if !strings.Contains(logs.String(), "reason=capacity") || !strings.Contains(logs.String(), "reason=store_integrity") {
		t.Fatal("missing loss reason", logs.String())
	}
}

func TestReleaseSignedURLRotationAndRestartKeepWarmObject(t *testing.T) {
	var gets, heads atomic.Int32
	service, client, _ := proxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"immutable"`)
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodHead {
			heads.Add(1)
			return
		}
		gets.Add(1)
		_, _ = io.WriteString(w, "payload")
	}))
	const source = "https://release-assets.githubusercontent.com/github-production-release-asset/123/456?sig="
	for _, signature := range []string{"first", "rotated"} {
		response, err := client.Get(source + signature)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(body) != "payload" {
			t.Fatal("release download failed", err)
		}
	}
	if gets.Load() != 1 || heads.Load() != 2 {
		t.Fatal("rotating credentials changed object identity")
	}
	service.Close()
	store, err := Open(service.store.dir, 1<<20, 1<<19, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	key := "release:release-assets.githubusercontent.com/github-production-release-asset/123/456\x00\"immutable\"\x007"
	if !readObject(t, store, key, 7, fill("wrong")) {
		t.Fatal("restart lost release object")
	}
}

func TestFillFailuresHaveSafeReasonsAndKeepUpstreamFallback(t *testing.T) {
	for _, mode := range []string{"status", "identity", "body"} {
		t.Run(mode, func(t *testing.T) {
			backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"immutable"`)
				w.Header().Set("Content-Length", "7")
				if r.Method == http.MethodHead {
					return
				}
				switch mode {
				case "status":
					w.WriteHeader(http.StatusForbidden)
				case "identity":
					w.Header().Set("ETag", `"changed"`)
					_, _ = io.WriteString(w, "payload")
				case "body":
					_, _ = io.WriteString(w, "short")
				}
			}))
			defer backend.Close()
			s, b, client := testService(t, backend)
			var logs bytes.Buffer
			s.log = slog.New(slog.NewJSONHandler(&logs, nil))
			local := makeLease(t, b, client, backend.URL+"/archive?sig=synthetic-private")
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			response, err := client.Get(local)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			// Before the first byte the guest is sent upstream. A short body has
			// already streamed: the fill resumes, this upstream ignores the range,
			// and the response ends early, as a failed direct download would.
			wantStatus, wantSummary := http.StatusTemporaryRedirect, Summary{Archives: Counters{Bypasses: 1, Failures: 1}}
			if mode == "body" {
				wantStatus, wantSummary = http.StatusOK, Summary{Archives: Counters{Misses: 1, MissBytes: 5, Failures: 1}}
			}
			waitSummary(t, s, wantSummary)
			want := map[string]string{"status": "upstream_status", "identity": "upstream_identity", "body": "upstream_resume"}[mode]
			if response.StatusCode != wantStatus || !strings.Contains(logs.String(), want) || strings.Contains(logs.String(), "synthetic-private") || strings.Contains(logs.String(), backend.URL) {
				t.Fatal("unsafe or missing diagnostic", logs.String())
			}
			if mode == "body" && !strings.Contains(logs.String(), `"msg":"cache fill resumed","object"`) {
				t.Fatal("short body was not resumed", logs.String())
			}
		})
	}
}

func TestFailureClassificationDoesNotRetainTransportDetails(t *testing.T) {
	for _, tc := range []struct {
		cause error
		want  string
	}{{context.Canceled, "canceled"}, {context.DeadlineExceeded, "timeout"}, {errors.New("synthetic-sensitive-diagnostic"), "upstream_transport"}} {
		original := &url.Error{Op: "Get", URL: "https://example.blob.core.windows.net/archive?sig=synthetic-private", Err: tc.cause}
		err := upstreamFailure(original)
		if reason, _ := failureDetails(err); reason != tc.want || strings.Contains(err.Error(), "synthetic") || errors.Is(err, original) {
			t.Fatal("transport classification retained private details or lost its category")
		}
	}
}
