package vz

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/manager"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/vm"
)

func linuxHelperFixture(t *testing.T) string {
	t.Helper()
	h := make([]byte, 64)
	copy(h, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 3})
	binary.LittleEndian.PutUint16(h[16:], 2)
	binary.LittleEndian.PutUint16(h[18:], 183)
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint16(h[52:], 64)
	path := filepath.Join(t.TempDir(), "linux-helper")
	if err := os.WriteFile(path, h, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func linuxRunnerManifest(t *testing.T, dir string) {
	t.Helper()
	writeTestManifest(t, dir, "linux")
	m, err := vm.ReadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	m.Guest.RunnerDir = "/opt/actions-runner"
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, vm.ManifestFile), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestGuestSelectionPreservesDarwinAndAdmitsLinuxWithoutInput(t *testing.T) {
	for _, guestOS := range []string{"darwin", "linux"} {
		t.Run(guestOS, func(t *testing.T) {
			r := newRecorder()
			p := newProvider(t, r)
			if guestOS == "linux" {
				p.runner = GuestRuntime{OS: guestOS, Helper: linuxHelperFixture(t)}
				linuxRunnerManifest(t, p.vmDir("base"))
			}
			spec := provider.Spec{Name: "bivouac-fixture-new", Baseline: "base", CPU: 2, MemoryMB: 4096, Meta: provider.Metadata{ControllerID: p.controllerID, InstanceID: "new"}}
			ctx := context.Background()
			if err := p.Create(ctx, spec); err != nil {
				t.Fatal(err)
			}
			// Neither launch nor readiness consults a disappeared baseline.
			if err := os.Remove(filepath.Join(p.vmDir("base"), vm.ManifestFile)); err != nil {
				t.Fatal(err)
			}
			if err := p.Start(ctx, spec.Name, io.Discard); err != nil {
				t.Fatal(err)
			}
			launch := strings.Join(r.calls[len(r.calls)-1], " ")
			if !strings.Contains(launch, "rootless-network") || strings.Contains(launch, " input ") != (guestOS == "darwin") {
				t.Fatal("guest-specific launch changed", launch)
			}
			r.session = "Background"
			err := p.WaitReady(ctx, spec.Name)
			if (err != nil) != (guestOS == "darwin") {
				t.Fatal("Aqua requirement not guest-specific", err)
			}
			if guestOS == "linux" {
				if err := p.StartRunner(ctx, spec.Name, []byte("synthetic-private-jit")); err == nil {
					t.Fatal("unfinished Linux runner adapter accepted JIT")
				}
				for key, value := range r.stdin {
					if strings.Contains(key, "tee "+guestPath) || strings.Contains(value, "synthetic-private-jit") {
						t.Fatal("Darwin bootstrap or JIT reached Linux guest")
					}
				}
			}
		})
	}
}

func TestHelperUploadSelectsCloneOS(t *testing.T) {
	for _, guestOS := range []string{"darwin", "linux"} {
		t.Run(guestOS, func(t *testing.T) {
			p, r := ownedFixture(t)
			source, destination := "", guestHelper
			if guestOS == "linux" {
				source = linuxHelperFixture(t)
				p.runner = GuestRuntime{OS: guestOS, Helper: source}
				linuxRunnerManifest(t, p.vmDir(fixtureName))
				destination = guestPath
			} else {
				var err error
				source, err = os.Executable()
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(filepath.Join(p.vmDir("base"), vm.ManifestFile)); err != nil {
				t.Fatal(err)
			}
			if err := p.installGuestHelper(context.Background(), fixtureName); err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			key := "Exec " + fixtureName + " dd of=" + destination + " status=none"
			if r.stdin[key] != string(want) {
				t.Fatal("wrong guest executable uploaded")
			}
			before := len(r.calls)
			if err := p.installGuestHelper(context.Background(), fixtureName); err != nil || len(r.calls) != before {
				t.Fatal("shared helper was recopied", err)
			}
		})
	}
}

func TestLinuxAdmissionRequiresRunnerContractAndMatchingHelper(t *testing.T) {
	for _, kind := range []string{"runner-directory", "helper-missing", "helper-invalid", "helper-architecture", "OS-mismatch"} {
		t.Run(kind, func(t *testing.T) {
			r := newRecorder()
			p := newProvider(t, r)
			helper := linuxHelperFixture(t)
			p.runner = GuestRuntime{OS: "linux", Helper: helper}
			linuxRunnerManifest(t, p.vmDir("base"))
			switch kind {
			case "runner-directory":
				writeTestManifest(t, p.vmDir("base"), "linux")
			case "helper-missing":
				if err := os.Remove(helper); err != nil {
					t.Fatal(err)
				}
			case "helper-invalid":
				if err := os.WriteFile(helper, []byte("not ELF"), 0600); err != nil {
					t.Fatal(err)
				}
			case "helper-architecture":
				b, err := os.ReadFile(helper)
				if err != nil {
					t.Fatal(err)
				}
				binary.LittleEndian.PutUint16(b[18:], 62)
				if err := os.WriteFile(helper, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "OS-mismatch":
				writeTestManifest(t, p.vmDir("base"), "darwin")
			}
			spec := provider.Spec{Name: "bivouac-fixture-new", Baseline: "base"}
			if err := p.Create(context.Background(), spec); err == nil {
				t.Fatal("invalid baseline/helper admitted")
			}
			if len(r.calls) != 0 {
				t.Fatal("admission failure touched VM runtime")
			}
		})
	}
}

type checkedRuntime struct {
	Runtime
	checks  int
	failure error
}

func (r *checkedRuntime) ProveIsolation(name, policy string) error {
	return r.Runtime.(interface{ ProveIsolation(string, string) error }).ProveIsolation(name, policy)
}
func (r *checkedRuntime) CheckRuntime(context.Context) error { r.checks++; return r.failure }

func TestStartupAndRetainedAdoptionIgnoreUnavailableBaseline(t *testing.T) {
	for _, kind := range []string{"missing", "changed"} {
		t.Run(kind, func(t *testing.T) {
			old, r := ownedFixture(t)
			if kind == "missing" {
				if err := os.RemoveAll(old.vmDir("base")); err != nil {
					t.Fatal(err)
				}
				delete(r.vms, "base")
			} else {
				writeTestManifest(t, old.vmDir("base"), "linux")
			}
			runtime := &checkedRuntime{Runtime: callRuntime{r}}
			p, err := New(old.name, old.cfg, old.runner, old.controllerID, string(old.store), runtime, nil)
			if err != nil {
				t.Fatal(err)
			}
			p.checkIsolation = func(context.Context) error { return nil }
			if err := p.CheckRuntime(context.Background()); err != nil || runtime.checks != 1 {
				t.Fatal("startup depends on admission inputs", err)
			}
			owned, _, err := p.List(context.Background())
			if err != nil || len(owned) != 1 {
				t.Fatal("retained clone inventory lost", err)
			}
			assertReconcilesRetainedRunner(t, p)
			status, err := p.RunnerStatus(context.Background(), fixtureName)
			if err != nil || status.State != provider.RunnerListening {
				t.Fatal("retained runner cannot be adopted", err)
			}
			spec := provider.Spec{Name: "bivouac-fixture-new", Baseline: "base"}
			if err := p.Create(context.Background(), spec); err == nil {
				t.Fatal("unavailable baseline admitted a new clone")
			}
			if err := p.Stop(context.Background(), fixtureName, time.Second); err != nil {
				t.Fatal(err)
			}
			if err := p.Delete(context.Background(), fixtureName); err != nil {
				t.Fatal(err)
			}
			st, err := p.Status(context.Background(), fixtureName)
			if err != nil || st.Exists {
				t.Fatal("retained clone cleanup failed", err)
			}
		})
	}
}

func TestStartupDoesNotValidateLinuxHelper(t *testing.T) {
	for _, kind := range []string{"missing", "invalid"} {
		t.Run(kind, func(t *testing.T) {
			p, _ := ownedFixture(t)
			helper := linuxHelperFixture(t)
			p.runner = GuestRuntime{OS: "linux", Helper: helper}
			linuxRunnerManifest(t, p.vmDir("base"))
			linuxRunnerManifest(t, p.vmDir(fixtureName))
			if kind == "missing" {
				if err := os.Remove(helper); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(helper, []byte("invalid helper"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			if err := p.CheckRuntime(ctx); err != nil {
				t.Fatal("startup opened Linux helper", err)
			}
			status, err := p.Status(ctx, fixtureName)
			if err != nil || !status.Exists || !status.Running || !status.Owned {
				t.Fatal("VM status opened Linux helper", err)
			}
			if err := p.Create(ctx, provider.Spec{Name: "bivouac-fixture-new", Baseline: "base"}); err == nil {
				t.Fatal("new admission ignored helper failure")
			}
			if err := p.Stop(ctx, fixtureName, time.Second); err != nil {
				t.Fatal("cleanup opened Linux helper", err)
			}
			if err := p.Delete(ctx, fixtureName); err != nil {
				t.Fatal("cleanup opened Linux helper", err)
			}
		})
	}
}

func TestHostRuntimeFailureStillBlocksStartup(t *testing.T) {
	p, _ := ownedFixture(t)
	failure := errors.New("host runtime unavailable")
	runtime := &checkedRuntime{Runtime: p.rt, failure: failure}
	p.rt = runtime
	if err := p.CheckRuntime(context.Background()); !errors.Is(err, failure) {
		t.Fatal("host runtime failure ignored", err)
	}
}

func TestNewDoesNotOpenLinuxAdmissionInputs(t *testing.T) {
	cfg := config.VZ{Baseline: "missing"}
	p, err := New("linux", cfg, GuestRuntime{OS: "linux", Helper: filepath.Join(t.TempDir(), "missing")}, "controller", t.TempDir(), callRuntime{newRecorder()}, nil)
	if err != nil {
		t.Fatal("constructor opened admission inputs", err)
	}
	p.checkIsolation = func(context.Context) error { return nil }
	if err := p.CheckRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func assertReconcilesRetainedRunner(t *testing.T, p *Provider) {
	t.Helper()
	cfg, err := config.Parse([]byte(config.Example))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Providers = map[string]config.Provider{p.name: {Type: "vz", VZ: &p.cfg}}
	store, err := state.Open(t.TempDir(), func() string { return p.controllerID })
	if err != nil {
		t.Fatal(err)
	}
	record := &state.Instance{ID: "fixture", Provider: p.name, Name: fixtureName, Phase: state.PhaseListening, ScaleSetID: 100, CreatedAt: time.Now()}
	if err := store.Put(record); err != nil {
		t.Fatal(err)
	}
	p.SetRecords(store)
	var logs bytes.Buffer
	m, err := manager.New(manager.Options{Config: cfg, Store: store, Providers: map[string]provider.Provider{p.name: p}, GitHub: github.NewFake(), Log: slog.New(slog.NewTextHandler(&logs, nil)), NewID: func() string { return "unused" }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	m.Wait()
	if !strings.Contains(logs.String(), "adopting running guest") {
		t.Fatal("reconciliation did not adopt retained runner")
	}
	if _, ok := store.Get(record.ID); !ok {
		t.Fatal("adopted record removed during controller shutdown")
	}
}

func TestPairRecoveryIgnoresMissingBaselineAndEngineHelper(t *testing.T) {
	p, r, spec := pairProvider(t)
	ctx := context.Background()
	if err := p.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(ctx, spec.Name, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"base", "linux-base"} {
		if err := os.RemoveAll(p.vmDir(name)); err != nil {
			t.Fatal(err)
		}
		delete(r.vms, name)
	}
	if err := os.Remove(p.cfg.Containers.Helper); err != nil {
		t.Fatal(err)
	}
	// The host capability gate is covered independently; this fixture needs none.
	p.cfg.Containers.Machine.NestedVirtualization = false
	restarted, err := New(p.name, p.cfg, p.runner, p.controllerID, string(p.store), callRuntime{r}, nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted.SetRecords(p.records)
	restarted.checkIsolation = func(context.Context) error { return nil }
	if err := restarted.CheckRuntime(ctx); err != nil {
		t.Fatal("startup depends on pair admission inputs", err)
	}
	status, err := restarted.RunnerStatus(ctx, spec.Name)
	if err != nil || status.State != provider.RunnerListening {
		t.Fatal("pair runner adoption blocked by missing baseline/helper", err)
	}
	if err := restarted.Create(ctx, spec); err == nil {
		t.Fatal("new pair admitted without baselines/helper")
	}
	if err := restarted.Stop(ctx, spec.Name, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Delete(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	statusVM, err := restarted.Status(ctx, spec.Name)
	if err != nil || statusVM.Exists {
		t.Fatal("retained pair cleanup failed", err)
	}
}
