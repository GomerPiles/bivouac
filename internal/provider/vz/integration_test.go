//go:build integration

package vz

// Real-host validation of the VM runtime. Run on an Apple Silicon Mac with a
// baseline imported into the VM store (BIVOUAC_HOME's when set) with the bivouac
// guest agent installed, and a bivouac binary signed with
// tools/macos/bivouac.entitlements:
//
//	BIVOUAC_VZ_BASELINE=<baseline> BIVOUAC_EXE=<signed bivouac> \
//	  go test -tags integration -run TestRealGuest -v ./internal/provider/vz/
//
// It clones the baseline twice, proves the guest agent session is Aqua, that
// the helper receives exactly its argument array and holds the VM lock, that
// a sentinel written in one clone is absent in the next, that cleanup refuses
// the baseline, and it prints clone, boot, and teardown timings.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/paths"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/vm"
)

func TestRealGuest(t *testing.T) {
	baseline := os.Getenv("BIVOUAC_VZ_BASELINE")
	if baseline == "" {
		t.Skip("BIVOUAC_VZ_BASELINE not set")
	}
	exe := os.Getenv("BIVOUAC_EXE")
	if exe == "" {
		t.Skip("BIVOUAC_EXE not set")
	}
	if os.Getenv("BIVOUAC_HOME") == "" || os.Getenv("BIVOUAC_VZ_CAPACITY_CONFIRMED") != "1" {
		t.Fatal("real guest validation requires an isolated home and confirmed CPU/memory/macOS slot reservations")
	}
	layout, err := paths.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	store := vm.Store(layout.VMs)
	cfg := config.VZ{Baseline: baseline, HostVMLimit: 2, ForeignSlots: 1}
	p, err := New("macos", cfg, GuestRuntime{OS: "darwin"}, "integration-ctl", layout.VMs, &local{store: store, exe: exe}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.State, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := (control.Files{Dir: layout.State}).Acquire()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Release() })
	records, err := state.Open(layout.State, func() string { return "integration-ctl" })
	if err != nil {
		t.Fatal(err)
	}
	if len(records.List()) != 0 {
		t.Fatal("isolated validation home has retained instances; finish cleanup before testing")
	}
	p.controllerID = records.ControllerID()
	p.SetRecords(records)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Cleanup must refuse the baseline outright.
	if err := p.Delete(ctx, baseline); !errors.Is(err, provider.ErrNotOwned) {
		t.Fatalf("Delete(baseline) = %v, want ErrNotOwned", err)
	}

	var sentinelName string
	for round := 1; round <= 2; round++ {
		name := "bivouac-macos-it" + strconv.FormatInt(time.Now().Unix(), 36)
		spec := provider.Spec{Name: name, Baseline: baseline, Meta: provider.Metadata{ControllerID: records.ControllerID(), InstanceID: name, CreatedAt: time.Now().UTC().Format(time.RFC3339)}}
		if err := records.Put(&state.Instance{ID: name, Name: name, Provider: "macos", Phase: state.PhaseCreating}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), time.Minute)
			defer done()
			if st, err := p.Status(cleanup, name); err == nil && st.Exists && st.Owned {
				_ = p.Stop(cleanup, name, time.Second)
				if err := p.Delete(cleanup, name); err != nil {
					t.Error("disposable guest cleanup failed")
				}
			}
		})
		t0 := time.Now()
		if err := p.Create(ctx, spec); err != nil {
			t.Fatal(err)
		}
		clone := time.Since(t0)
		launchLog := &bytes.Buffer{}
		t1 := time.Now()
		if err := p.Start(ctx, name, launchLog); err != nil {
			t.Fatal(err)
		}
		if err := p.WaitReady(ctx, name); err != nil {
			t.Fatal(err)
		}
		boot := time.Since(t1)
		validateGuestIsolation(t, ctx, p, name)

		// The launched process carries exactly our argument array.
		pid := p.LaunchPID(name)
		ps, err := exec.Command("/bin/ps", "-o", "args=", "-p", strconv.Itoa(pid)).Output()
		if err != nil {
			t.Fatal(err)
		}
		args := strings.TrimSpace(string(ps))
		launchArgs, err := p.LaunchArgs(name)
		if err != nil {
			t.Fatal(err)
		}
		if want := strings.Join(append([]string{exe}, launchArgs...), " "); args != want {
			t.Fatal("VM helper argument array differs from the rootless launch plan")
		}
		if holder, err := vm.Holder(store.Dir(name)); err != nil || holder != pid {
			t.Fatalf("lock holder = %d, %v; want helper %d", holder, err, pid)
		}
		t.Logf("round %d: rootless helper argument array and lock verified", round)

		// The guest agent runs commands in the Aqua session.
		out, err := p.output(ctx, name, []string{guestPath, "session"}, nil)
		if err != nil || strings.TrimSpace(string(out)) != "Aqua" {
			t.Fatalf("guest session = %q, %v; want Aqua", out, err)
		}

		// Sentinel: present in the clone that wrote it, absent in the next.
		sentinel := "/Users/admin/bivouac-sentinel"
		if _, err := p.output(ctx, name, []string{"ls", sentinel}, nil); err == nil {
			t.Fatalf("round %d: sentinel from a previous guest is present", round)
		}
		if _, err := p.output(ctx, name, []string{"touch", sentinel}, nil); err != nil {
			t.Fatal(err)
		}
		sentinelName = name

		st, err := p.RunnerStatus(ctx, name)
		if err != nil || st.State != provider.RunnerAbsent {
			t.Fatalf("runner status before start = %+v, %v", st, err)
		}

		dir := filepath.Join(t.TempDir(), "diag")
		if err := p.CollectDiagnostics(ctx, name, dir); err != nil {
			t.Logf("diagnostics (runner never started, so partial): %v", err)
		}

		t2 := time.Now()
		if err := p.Stop(ctx, name, 30*time.Second); err != nil {
			t.Fatal(err)
		}
		if err := p.Delete(ctx, name); err != nil {
			t.Fatal(err)
		}
		if err := records.Remove(name); err != nil {
			t.Fatal(err)
		}
		teardown := time.Since(t2)
		t.Logf("round %d: clone %s, boot-to-agent %s, teardown %s", round, clone.Round(time.Millisecond), boot.Round(time.Millisecond), teardown.Round(time.Millisecond))
		if st, _ := p.Status(ctx, name); st.Exists {
			t.Fatalf("%s still exists after delete", name)
		}
	}
	_ = sentinelName

	owned, foreign, err := p.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 0 {
		t.Fatalf("owned guests left: %v", owned)
	}
	t.Logf("foreign guests on host: %d", len(foreign))
	if st, _ := p.Status(ctx, baseline); !st.Exists {
		t.Fatal("baseline vanished")
	}
}
