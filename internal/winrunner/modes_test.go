package winrunner

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func readyFacts() (Config, preflightFacts) {
	return Config{NativeName: "GUEST", User: "runner"}, preflightFacts{
		computer: "guest", user: "RUNNER", consoleUser: "Runner", desktop: "Default", console: 1, process: 1, explorer: true,
	}
}

func TestPrepareInstanceCheck(t *testing.T) {
	cfg := Config{RunnerName: "bivouac-windows-01234567", ControllerID: "controller"}
	for _, previous := range []Config{cfg, {RunnerName: cfg.RunnerName, ControllerID: "other"}, {RunnerName: "bivouac-windows-89abcdef", ControllerID: cfg.ControllerID}} {
		data, err := json.Marshal(previous)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkPrepareInstance(data, cfg); (err == nil) != (previous == cfg) {
			t.Fatal("instance check differs", err)
		}
	}
	if err := checkPrepareInstance([]byte("invalid"), cfg); err == nil {
		t.Fatal("accepted malformed previous config")
	}
}

func TestRunnerArchiveHash(t *testing.T) {
	archive := makeRunnerZip(t, []string{"bin/Runner.Listener.exe"}, 0o600)
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	if err := VerifyArchive(archive, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal("verified archive refused", err)
	}
	if err := VerifyArchive(archive, strings.Repeat("0", 64)); err == nil {
		t.Fatal("archive with different hash accepted")
	}
}

func TestRunnerArchiveEntryCountBound(t *testing.T) {
	var data bytes.Buffer
	z := zip.NewWriter(&data)
	for range maxRunnerFiles + 1 {
		if _, err := z.CreateRaw(&zip.FileHeader{Name: "entry"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "too-many.zip")
	if err := os.WriteFile(archive, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractRunner(t.Context(), archive, filepath.Join(t.TempDir(), "runner")); err == nil || !strings.Contains(err.Error(), "entry bound") {
		t.Fatal("archive entry bound was not enforced", err)
	}
}

func TestPreflightDecisions(t *testing.T) {
	cfg, good := readyFacts()
	if !preflightReady(cfg, good) {
		t.Fatal("ready console refused")
	}
	for _, change := range []func(*preflightFacts){
		func(f *preflightFacts) { f.computer = "other" }, func(f *preflightFacts) { f.user = "other" },
		func(f *preflightFacts) { f.consoleUser = "other" }, func(f *preflightFacts) { f.console = 0 },
		func(f *preflightFacts) { f.console = ^uint32(0) }, func(f *preflightFacts) { f.process = 2 },
		func(f *preflightFacts) { f.desktop = "Winlogon" }, func(f *preflightFacts) { f.setup = 1 },
		func(f *preflightFacts) { f.oobe = 1 }, func(f *preflightFacts) { f.explorer = false },
	} {
		bad := good
		change(&bad)
		if preflightReady(cfg, bad) {
			t.Fatal("accepted incomplete or different desktop")
		}
	}
}

func TestPreflightConsecutivePassesAndDeadline(t *testing.T) {
	cfg, good := readyFacts()
	calls, pauses := 0, 0
	proof, err := waitPreflight(t.Context(), cfg, func() (preflightFacts, error) {
		calls++
		if calls == 3 { // A failed observation discards both earlier passes.
			return good, errors.New("transient read")
		}
		return good, nil
	}, func(context.Context) error { pauses++; return nil })
	if err != nil || calls != 8 || pauses != 7 || proof != (desktopProof{true, 1, "Default"}) {
		t.Fatal(proof, calls, pauses, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, err = waitPreflight(ctx, cfg, func() (preflightFacts, error) { return preflightFacts{}, nil }, func(context.Context) error { cancel(); return ctx.Err() })
	if err == nil {
		t.Fatal("preflight escaped deadline")
	}
	if err := pauseGuest(ctx, 500*time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatal("pause ignored cancellation", err)
	}
}

func TestStaticNetworkPlan(t *testing.T) {
	mac := net.HardwareAddr{2, 0, 0, 1, 2, 3}
	cfg := Config{MAC: "02-00-00-01-02-03", Address: "10.251.0.2", Gateway: "10.251.0.1", Prefix: 28}
	adapters := []net.Interface{{Index: 3, HardwareAddr: net.HardwareAddr{2, 0, 0, 4, 5, 6}}, {Index: 7, HardwareAddr: mac}}
	plan, err := networkPlan(cfg, adapters)
	want := [][]string{
		{"interface", "ipv4", "set", "address", "name=7", "source=static", "address=10.251.0.2", "mask=255.255.255.240", "gateway=10.251.0.1", "gwmetric=1", "store=persistent"},
		{"interface", "ipv4", "set", "dnsservers", "name=7", "source=static", "address=1.1.1.1", "register=none", "validate=no"},
		{"interface", "ipv4", "add", "dnsservers", "name=7", "address=8.8.8.8", "index=2", "validate=no"},
	}
	if err != nil || !reflect.DeepEqual(plan, want) {
		t.Fatal(plan, err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.MAC = "invalid" }, func(c *Config) { c.Address = "10.251.0.2 & whoami" },
		func(c *Config) { c.Address = "::1" }, func(c *Config) { c.Gateway = "10.252.0.1" },
		func(c *Config) { c.Prefix = 0 }, func(c *Config) { c.Prefix = 33 },
	} {
		bad := cfg
		change(&bad)
		if _, err := networkPlan(bad, adapters); err == nil {
			t.Fatal("accepted invalid network settings")
		}
	}
	for _, list := range [][]net.Interface{adapters[:1], append(adapters, adapters[1])} {
		if _, err := networkPlan(cfg, list); err == nil {
			t.Fatal("accepted missing or duplicate owned MAC")
		}
	}
}

func makeRunnerZip(t *testing.T, names []string, mode os.FileMode) string {
	t.Helper()
	var data bytes.Buffer
	z := zip.NewWriter(&data)
	for _, name := range names {
		h := &zip.FileHeader{Name: name, Method: zip.Store}
		h.SetMode(mode)
		w, err := z.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("generic runner fixture")); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "runner.zip")
	if err := os.WriteFile(file, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestRunnerExtractionPathsAndLinks(t *testing.T) {
	for _, name := range []string{"../outside", `a\..\outside`, "/outside", `C:\outside`, `\\server\share\file`, "file:stream", "CON", "bin/COM1.txt", "bin/file. ", "a//b", "a/./b", "file\x00", "a?b"} {
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			archive := makeRunnerZip(t, []string{name}, 0o600)
			dest := filepath.Join(t.TempDir(), "runner")
			if err := extractRunner(t.Context(), archive, dest); err == nil {
				t.Fatal("accepted unsafe archive")
			}
			if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe archive created output")
			}
		})
	}
	for _, mode := range []os.FileMode{os.ModeSymlink | 0o777, os.ModeNamedPipe | 0o600, os.ModeDevice | 0o600} {
		archive := makeRunnerZip(t, []string{"link"}, mode)
		if err := extractRunner(t.Context(), archive, filepath.Join(t.TempDir(), "runner")); err == nil {
			t.Fatal("accepted special archive entry")
		}
	}
	for _, names := range [][]string{{"bin/tool", "BIN/TOOL"}, {"bin/tool", `bin\tool`}} {
		if err := extractRunner(t.Context(), makeRunnerZip(t, names, 0o600), filepath.Join(t.TempDir(), "runner")); err == nil {
			t.Fatal("accepted duplicate Windows paths")
		}
	}
}

func TestRunnerExtractionBoundsFreshnessAndSuccess(t *testing.T) {
	archive := makeRunnerZip(t, []string{"bin/Runner.Listener.exe"}, 0o600)
	dest := filepath.Join(t.TempDir(), "runner")
	if err := extractRunner(t.Context(), archive, dest); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(filepath.Join(dest, "bin", "Runner.Listener.exe")); err != nil || string(content) != "generic runner fixture" {
		t.Fatal("extracted content differs", err)
	}
	if err := extractRunner(t.Context(), archive, dest); err == nil {
		t.Fatal("reused runner directory")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := extractRunner(ctx, archive, filepath.Join(t.TempDir(), "runner")); !errors.Is(err, context.Canceled) {
		t.Fatal("extraction ignored cancellation", err)
	}
	for _, sizes := range [][]uint64{{maxRunnerFile + 1}, {maxRunnerFile, maxRunnerFile, maxRunnerFile, maxRunnerFile, 1}} {
		var data bytes.Buffer
		z := zip.NewWriter(&data)
		for i, size := range sizes {
			h := &zip.FileHeader{Name: string(rune('a' + i)), UncompressedSize64: size}
			h.SetMode(0o600)
			if _, err := z.CreateRaw(h); err != nil {
				t.Fatal(err)
			}
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "oversize.zip")
		if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := extractRunner(t.Context(), path, filepath.Join(t.TempDir(), "runner")); err == nil {
			t.Fatal("accepted expansion beyond bound")
		}
	}
}

func TestClockInputBounds(t *testing.T) {
	for _, input := range []string{"2026-10-22T21:00:00Z", "2026-10-22T21:00:00.123456789Z\n", "2026-10-22T21:00:00Z\r\n"} {
		if value, err := parseClock(strings.NewReader(input)); err != nil || value.Location() != time.UTC {
			t.Fatal("valid UTC refused", err)
		}
	}
	for _, input := range []string{"", strings.Repeat("x", 66), "2026-10-22T21:00:00+01:00", "2026-10-22T21:00:00Z\nextra", "2026-10-22T21:00:00Z\n\n", "1600-01-01T00:00:00Z", "10000-01-01T00:00:00Z", "2026-99-99T00:00:00Z", "2026-10-22T21:00:00Z "} {
		if _, err := parseClock(strings.NewReader(input)); err == nil {
			t.Fatal("invalid clock input accepted")
		}
	}
}

func guestTestRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func TestStartMarkerBeforeLaunchAndNoReplay(t *testing.T) {
	root := guestTestRoot(t)
	if err := root.WriteFile("jit", []byte("synthetic input"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	launch := func() error {
		calls++
		if exists, err := guestFileExists(root, "launched"); err != nil || !exists {
			t.Fatal("dispatch preceded launch marker", err)
		}
		return errors.New("uncertain dispatch")
	}
	if err := markAndLaunch(root, launch); err == nil || calls != 1 {
		t.Fatal("expected uncertain dispatch")
	}
	if err := markAndLaunch(root, launch); err == nil || calls != 1 {
		t.Fatal("replayed dispatch")
	}
}

func TestStartSingleUseAndJITRefusals(t *testing.T) {
	for _, marker := range []string{"launched", "launch-once", "listener.json", "runner.exit", "missing-jit", "empty-jit", "oversize-jit", "success"} {
		t.Run(marker, func(t *testing.T) {
			root := guestTestRoot(t)
			if !strings.HasSuffix(marker, "-jit") {
				if err := root.WriteFile("jit", []byte("synthetic input"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if marker == "empty-jit" || marker == "oversize-jit" {
				n := 0
				if marker == "oversize-jit" {
					n = 128<<10 + 1
				}
				if err := root.WriteFile("jit", make([]byte, n), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if marker != "missing-jit" && marker != "success" {
				if err := root.WriteFile(marker, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			err := markAndLaunch(root, func() error { called = true; return nil })
			if marker == "success" {
				if err != nil || !called {
					t.Fatal("valid launch refused", err)
				}
			} else if err == nil || called {
				t.Fatal("unsafe launch dispatched")
			}
		})
	}
}

func TestStopNoOpCasesAndDispatch(t *testing.T) {
	for _, state := range []string{"absent", "launched", "runner.exit"} {
		root := guestTestRoot(t)
		if state != "absent" {
			if err := root.WriteFile("listener.json", nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if state == "runner.exit" {
			if err := root.WriteFile("runner.exit", nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		called := false
		if err := stopGuest(root, func() error { called = true; return nil }); err != nil || called != (state == "launched") {
			t.Fatal("stop semantics differ", state, called, err)
		}
	}
}
