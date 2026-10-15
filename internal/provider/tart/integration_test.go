//go:build integration

package tart

// Real-host validation against the Tart CLI. Run on an Apple Silicon Mac
// with a local baseline:
//
//	BIVOUAC_TART_BASELINE=<baseline> go test -tags integration -run TestRealGuest -v ./internal/provider/tart/
//
// It clones the baseline twice, proves the guest agent session is Aqua, that
// `--no-graphics` and extra arguments reach the launched process, that a
// sentinel written in one clone is absent in the next, that cleanup refuses
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
	"github.com/GomerPiles/bivouac/internal/provider"
)

func TestRealGuest(t *testing.T) {
	baseline := os.Getenv("BIVOUAC_TART_BASELINE")
	if baseline == "" {
		t.Skip("BIVOUAC_TART_BASELINE not set")
	}
	cfg := config.Tart{Baseline: baseline, ExtraArgs: []string{"--no-audio", "--no-clipboard"}, RunnerDir: "/Users/admin/actions-runner", Binary: "tart", HostVMLimit: 2, ForeignSlots: 1}
	p, err := New("macos", cfg, "integration-ctl", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Cleanup must refuse the baseline outright.
	if err := p.Delete(ctx, baseline); !errors.Is(err, provider.ErrNotOwned) {
		t.Fatalf("Delete(baseline) = %v, want ErrNotOwned", err)
	}

	var sentinelName string
	for round := 1; round <= 2; round++ {
		name := "bivouac-macos-it" + strconv.FormatInt(time.Now().Unix(), 36)
		spec := provider.Spec{Name: name, Baseline: baseline, Launch: provider.Launch{Args: cfg.ExtraArgs}, Meta: provider.Metadata{ControllerID: "integration-ctl", InstanceID: name, CreatedAt: time.Now().UTC().Format(time.RFC3339)}}
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

		// The launched process carries exactly our argument array.
		pid := p.LaunchPID(name)
		ps, err := exec.Command("/bin/ps", "-o", "args=", "-p", strconv.Itoa(pid)).Output()
		if err != nil {
			t.Fatal(err)
		}
		args := strings.TrimSpace(string(ps))
		for _, want := range []string{"--no-graphics", "--no-audio", "--no-clipboard", name} {
			if !strings.Contains(args, want) {
				t.Fatalf("launched process %q lacks %q", args, want)
			}
		}
		t.Logf("round %d: tart run process: %s", round, args)

		// The guest agent runs commands in the Aqua session.
		out, err := p.output(ctx, []string{"exec", name, guestPath, "session"}, nil)
		if err != nil || strings.TrimSpace(string(out)) != "Aqua" {
			t.Fatalf("guest session = %q, %v; want Aqua", out, err)
		}

		// Sentinel: present in the clone that wrote it, absent in the next.
		sentinel := "/Users/admin/bivouac-sentinel"
		if _, err := p.output(ctx, []string{"exec", name, "ls", sentinel}, nil); err == nil {
			t.Fatalf("round %d: sentinel from a previous guest is present", round)
		}
		if _, err := p.output(ctx, []string{"exec", name, "touch", sentinel}, nil); err != nil {
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
