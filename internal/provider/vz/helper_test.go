package vz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/engine"
	"github.com/GomerPiles/bivouac/internal/vm"
)

func enableFixtureCache(t *testing.T, p *Provider) {
	t.Helper()
	service, err := cache.Start(t.TempDir(), "127.0.0.1:0", "127.0.0.1", 1<<30, 1<<20, time.Minute, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	service.EnableReleaseProxy()
	p.SetCache(service)
}

func helperUploads(r *recorder, name string) int {
	count := 0
	for _, call := range r.calls {
		if len(call) > 3 && call[0] == "Exec" && call[1] == name && call[2] == "dd" && call[3] == "of="+guestHelper {
			count++
		}
	}
	return count
}

func TestRunnerSharesOneHelperWithCache(t *testing.T) {
	p, r := ownedFixture(t)
	enableFixtureCache(t, p)
	var logs bytes.Buffer
	p.log = slog.New(slog.NewJSONHandler(&logs, nil))
	if err := p.StartRunner(context.Background(), fixtureName, []byte("synthetic-private-jit")); err != nil {
		t.Fatal(err)
	}
	if got := helperUploads(r, fixtureName); got != 1 {
		t.Fatalf("uploaded %d macOS helpers, want 1", got)
	}
	if _, ok := r.stdin["Exec "+fixtureName+" dd of=/tmp/bivouac/cache-config.json status=none"]; !ok {
		t.Fatal("cache bootstrap was not delivered")
	}
	prepared := false
	for _, call := range r.calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "bivouac-cache-client") || strings.Contains(joined, "of="+engine.GuestHelper) || strings.Contains(joined, "synthetic-private-jit") {
			t.Fatal("duplicate helper destination or private input in argv")
		}
		if len(call) > 3 && call[2] == "/usr/bin/install" && call[len(call)-1] == guestHelper && !prepared {
			t.Fatal("runtime leaf was not removed before installing a helper")
		}
		prepared = prepared || joined == "Exec "+fixtureName+" rm -f "+guestHelper
	}
	if strings.Contains(logs.String(), "synthetic-private-jit") || strings.Contains(logs.String(), "BEGIN CERTIFICATE") {
		t.Fatal("startup logs retain private input")
	}
	stages := map[string]bool{}
	decoder := json.NewDecoder(&logs)
	for decoder.More() {
		var record struct {
			Message    string `json:"msg"`
			Name       string `json:"name"`
			Provider   string `json:"provider"`
			Stage      string `json:"stage"`
			DurationMS int64  `json:"duration_ms"`
			Success    bool   `json:"success"`
		}
		if err := decoder.Decode(&record); err != nil {
			t.Fatal(err)
		}
		if record.Message != "startup stage" || !record.Success || record.Name != fixtureName || record.Provider != p.name || record.DurationMS < 0 {
			t.Fatal("missing or invalid startup observation")
		}
		stages[record.Stage] = true
	}
	for _, stage := range []string{"helper_upload", "cache_setup", "jit_delivery"} {
		if !stages[stage] {
			t.Fatalf("missing %s timing", stage)
		}
	}
}

func TestHelperUploadFailureDoesNotRetainGuestOutput(t *testing.T) {
	p, r := ownedFixture(t)
	p.rt = callRuntime{&failedHelper{recorder: r}}
	var logs bytes.Buffer
	p.log = slog.New(slog.NewJSONHandler(&logs, nil))
	err := p.installGuestHelper(context.Background(), fixtureName)
	if err == nil {
		t.Fatal("failed upload succeeded")
	}
	if strings.Contains(err.Error(), "private") || strings.Contains(logs.String(), "private") {
		t.Fatal("guest-controlled data retained")
	}
	if !strings.Contains(logs.String(), `"stage":"helper_upload"`) || !strings.Contains(logs.String(), `"success":false`) {
		t.Fatal("failed stage timing missing")
	}
}

type cacheInstallFailure struct{ *recorder }

func (f cacheInstallFailure) Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if strings.Contains(strings.Join(args, " "), "dd of=/tmp/bivouac-cache-preload.cjs") {
		return errors.New("synthetic cache installation failure")
	}
	return f.recorder.Run(ctx, args, stdin, stdout)
}

func TestCacheFailurePreservesSharedHelper(t *testing.T) {
	p, r := ownedFixture(t)
	enableFixtureCache(t, p)
	p.rt = callRuntime{cacheInstallFailure{r}}
	if err := p.StartRunner(context.Background(), fixtureName, []byte("synthetic-jit")); err != nil {
		t.Fatal(err)
	}
	installed := false
	for _, call := range r.calls {
		installed = installed || strings.Join(call, " ") == "Exec "+fixtureName+" chmod 0700 "+guestHelper
		if installed && len(call) > 3 && call[2] == "rm" {
			for _, arg := range call[3:] {
				if arg == guestHelper {
					t.Fatal("cache fallback removed the telemetry/relay helper")
				}
			}
		}
	}
	if helperUploads(r, fixtureName) != 1 {
		t.Fatal("cache fallback recopied the helper")
	}
}

func TestPairReusesMacOSHelperAtRunnerStart(t *testing.T) {
	p, r, spec := pairProvider(t)
	enableFixtureCache(t, p)
	p.startRelay = func(context.Context, RelayPlan) (Process, error) {
		return &fakeProc{done: make(chan struct{})}, nil
	}
	ctx := context.Background()
	if err := p.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(ctx, spec.Name, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := p.WaitReady(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	if err := p.StartRunner(ctx, spec.Name, []byte("synthetic-jit")); err != nil {
		t.Fatal(err)
	}
	if helperUploads(r, spec.Name) != 1 {
		t.Fatal("macOS helper was recopied after starting the relay")
	}
	linuxCopies := 0
	for _, call := range r.calls {
		if len(call) > 3 && call[2] == "dd" && call[3] == "of="+engine.GuestHelper {
			if call[1] != spec.Name+"-engine" {
				t.Fatal("macOS guest received an extra container helper")
			}
			linuxCopies++
		}
	}
	if linuxCopies != 1 {
		t.Fatal("Linux companion helper delivery changed")
	}
}

type failedHelper struct {
	*recorder
	cleanupFails bool
	copyFailed   bool
}

func (f *failedHelper) Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if strings.Contains(strings.Join(args, " "), "dd of="+guestHelper) {
		f.copyFailed = true
		if _, err := io.WriteString(stdout, "synthetic-private-guest-output"); err != nil {
			return err
		}
		return errors.New("synthetic-private-copy-error")
	}
	if f.copyFailed && f.cleanupFails && len(args) >= 3 && args[len(args)-1] == guestHelper && args[len(args)-3] == "rm" {
		return errors.New("synthetic cleanup failure")
	}
	return f.recorder.Run(ctx, args, stdin, stdout)
}

func TestPartialHelperInstallationFallsBackOnlyAfterRemoval(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		r := newRecorder()
		p := newProvider(t, r)
		enableFixtureCache(t, p)
		writeMarker(t, p, "bivouac-macos-fixture")
		p.rt = callRuntime{&failedHelper{recorder: r, cleanupFails: cleanupFails}}
		err := p.StartRunner(context.Background(), "bivouac-macos-fixture", []byte("synthetic-jit"))
		if (err != nil) != cleanupFails {
			t.Fatal("partial helper cleanup outcome", err)
		}
		started := false
		for _, call := range r.calls {
			if strings.Contains(strings.Join(call, " "), "of=/tmp/bivouac/cache-config.json") {
				t.Fatal("cache setup continued without the shared helper")
			}
			if strings.Contains(strings.Join(call, " "), guestPath+" start") {
				started = true
			}
		}
		if started == cleanupFails {
			t.Fatal("JIT dispatched before partial helper removal")
		}
	}
}

type cacheCleanupFailure struct{ cacheInstallFailure }

func (f cacheCleanupFailure) Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if strings.Contains(strings.Join(args, " "), "rm -f /tmp/bivouac/cache-config.json") {
		return errors.New("synthetic cache cleanup uncertainty")
	}
	return f.cacheInstallFailure.Run(ctx, args, stdin, stdout)
}
func TestCacheFallbackRequiresProvenRemovalBeforeJIT(t *testing.T) {
	p, r := ownedFixture(t)
	p.rt = callRuntime{cacheCleanupFailure{cacheInstallFailure{r}}}
	enableFixtureCache(t, p)
	if err := p.StartRunner(context.Background(), fixtureName, []byte("synthetic-private-jit")); err == nil {
		t.Fatal("uncertain cache cleanup accepted JIT")
	}
	for _, call := range r.calls {
		if len(call) > 3 && call[0] == "Exec" && call[2] == guestPath && call[3] == "start" {
			t.Fatal("JIT delivery attempted despite uncertain cache cleanup")
		}
	}
}

func TestDarwinCacheKeepsArchivesWithOptionalSudo(t *testing.T) {
	for _, sudo := range []bool{false, true} {
		t.Run(map[bool]string{false: "without-sudo", true: "with-sudo"}[sudo], func(t *testing.T) {
			p, r := ownedFixture(t)
			manifest, err := vm.ReadManifest(p.vmDir(fixtureName))
			if err != nil {
				t.Fatal(err)
			}
			manifest.Guest.Sudo = sudo
			data, _ := json.Marshal(manifest)
			if err := os.WriteFile(filepath.Join(p.vmDir(fixtureName), vm.ManifestFile), data, 0600); err != nil {
				t.Fatal(err)
			}
			enableFixtureCache(t, p)
			if err := p.StartRunner(context.Background(), fixtureName, []byte("synthetic-jit")); err != nil {
				t.Fatal(err)
			}
			var bootstrap cache.Bootstrap
			if err := json.Unmarshal([]byte(r.stdin["Exec "+fixtureName+" dd of=/tmp/bivouac/cache-config.json status=none"]), &bootstrap); err != nil {
				t.Fatal("archive config missing", err)
			}
			if bootstrap.ReleaseProxy != sudo || bootstrap.Token == "" || bootstrap.CA == "" {
				t.Fatal("sudo gate removed ordinary cache capability")
			}
			assertVZGrantReleaseCapability(t, p.cache, bootstrap, sudo)
			trust, remove, preload, jit := false, false, -1, -1
			for index, call := range r.calls {
				text := strings.Join(call, " ")
				trust = trust || strings.Contains(text, guestPath+" cache-setup") || strings.Contains(text, "of=/tmp/bivouac-cache-ca.pem")
				remove = remove || strings.Contains(text, "rm -f /tmp/bivouac-cache-env /tmp/bivouac-cache-roots.pem /tmp/bivouac-cache-ca.pem")
				if strings.Contains(text, "dd of=/tmp/bivouac-cache-preload.cjs") {
					preload = index
				}
				if strings.Contains(text, guestPath+" start") {
					jit = index
				}
			}
			if trust != sudo || remove == sudo || preload < 0 || jit <= preload {
				t.Fatal("archive/preload/JIT or release trust ordering differs")
			}
		})
	}
}

// Valid grants must keep archive access while the host, independently of the
// bootstrap flag, enforces release authority. Unsupported ports prove positive
// authorization without opening an upstream socket in these offline tests.
func assertVZGrantReleaseCapability(t *testing.T, service *cache.Service, bootstrap cache.Bootstrap, release bool) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+bootstrap.Token)
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatal("archive grant lost ordinary access")
	}
	for _, method := range []string{http.MethodConnect, http.MethodGet} {
		request := httptest.NewRequest(method, "https://github.com:444/", nil)
		request.Header.Set("Proxy-Authorization", "Bearer "+bootstrap.Token)
		response := httptest.NewRecorder()
		service.ServeHTTP(response, request)
		want := http.StatusProxyAuthRequired
		if release {
			want = http.StatusForbidden
		}
		if response.Code != want {
			t.Fatal("host grant release authority differs", method, response.Code)
		}
	}
}
