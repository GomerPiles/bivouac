package vz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/engine"
)

func selfFingerprint(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

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
	fingerprint := selfFingerprint(t)
	for _, report := range []string{"absent", "untrusted", strings.Repeat("0", 64), fingerprint} {
		t.Run(report[:min(10, len(report))], func(t *testing.T) {
			p, r := ownedFixture(t)
			r.helperReport = report + "\n"
			enableFixtureCache(t, p)
			var logs bytes.Buffer
			p.SetLogger(slog.New(slog.NewJSONHandler(&logs, nil)))
			if err := p.StartRunner(context.Background(), fixtureName, []byte("synthetic-private-jit")); err != nil {
				t.Fatal(err)
			}
			want := 1
			if report == fingerprint {
				want = 0
			}
			if got := helperUploads(r, fixtureName); got != want {
				t.Fatalf("uploaded %d macOS helpers, want %d", got, want)
			}
			if _, ok := r.stdin["Exec "+fixtureName+" dd of=/tmp/bivouac/cache-config.json status=none"]; !ok {
				t.Fatal("cache bootstrap was not delivered")
			}
			linked := false
			prepared := false
			for _, call := range r.calls {
				joined := strings.Join(call, " ")
				if strings.Contains(joined, "bivouac-cache-client") || strings.Contains(joined, "of="+engine.GuestHelper) || strings.Contains(joined, "synthetic-private-jit") {
					t.Fatal("duplicate helper destination or private input in argv")
				}
				linked = linked || joined == "Exec "+fixtureName+" /bin/ln -s "+preparedHelper+" "+guestHelper
				if len(call) > 3 && (call[2] == "/usr/bin/install" || call[2] == "/bin/ln") && call[len(call)-1] == guestHelper && !prepared {
					t.Fatal("runtime leaf was not removed before installing/linking a helper")
				}
				prepared = prepared || joined == "Exec "+fixtureName+" rm -f "+guestHelper
			}
			if linked != (report == fingerprint) {
				t.Fatal("baseline helper used without an exact fingerprint")
			}
			if strings.Contains(logs.String(), "synthetic-private-jit") || strings.Contains(logs.String(), fingerprint) || strings.Contains(logs.String(), "BEGIN CERTIFICATE") {
				t.Fatal("startup logs retain private input or helper report")
			}
			stages := map[string]map[string]any{}
			decoder := json.NewDecoder(&logs)
			for decoder.More() {
				var record map[string]any
				if err := decoder.Decode(&record); err != nil {
					t.Fatal(err)
				}
				if record["msg"] != "macos startup stage" || record["success"] != true || record["name"] != fixtureName || record["duration_ms"].(float64) < 0 {
					t.Fatal("missing or invalid startup observation")
				}
				stages[record["stage"].(string)] = record
			}
			for _, stage := range []string{"helper_check", "helper_prepare", "cache_setup", "jit_delivery"} {
				if stages[stage] == nil {
					t.Fatalf("missing %s timing", stage)
				}
			}
			if stages["helper_prepare"]["helper_reused"] != (report == fingerprint) {
				t.Fatal("helper reuse outcome missing")
			}
		})
	}
}

func TestHelperProbeFailureDoesNotUploadOrRetainGuestOutput(t *testing.T) {
	for _, report := range []string{"malformed-private-report", strings.Repeat("x", 129), "transport"} {
		p, r := ownedFixture(t)
		r.helperReport = report
		if report == "transport" {
			r.helperErr = errors.New("synthetic-private-transport-error")
		}
		var logs bytes.Buffer
		p.SetLogger(slog.New(slog.NewJSONHandler(&logs, nil)))
		err := p.installGuestHelper(context.Background(), fixtureName)
		if err == nil || helperUploads(r, fixtureName) != 0 {
			t.Fatal("failed probe triggered an upload")
		}
		if strings.Contains(err.Error(), "private") || strings.Contains(logs.String(), "private") {
			t.Fatal("guest-controlled data retained")
		}
		if !strings.Contains(logs.String(), `"stage":"helper_check"`) || !strings.Contains(logs.String(), `"success":false`) {
			t.Fatal("failed stage timing missing")
		}
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
		return errors.New("synthetic partial copy failure")
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
