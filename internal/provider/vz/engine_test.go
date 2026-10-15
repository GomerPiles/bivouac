package vz

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/vm"
)

func pairProvider(t *testing.T) (*Provider, *recorder, provider.Spec) {
	t.Helper()
	r := newRecorder()
	r.vms["linux-base"] = false
	p := newProvider(t, r)
	p.records, _ = state.Open(t.TempDir(), func() string { return "ctl-1" })
	name := "bivouac-macos-pair"
	i := &state.Instance{ID: "pair", Provider: "macos", Name: name, EngineName: name + "-engine", ContainerEngine: "docker", CPU: 6, MemoryGB: 10, Phase: state.PhaseCreating}
	if err := p.records.Put(i); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{name, name + "-engine"} {
		if err := os.MkdirAll(p.vmDir(n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, b := range []struct{ name, os string }{{"base", "darwin"}, {"linux-base", "linux"}} {
		data, _ := json.Marshal(map[string]string{"os": b.os, "arch": "arm64"})
		if err := os.WriteFile(filepath.Join(p.vmDir(b.name), "config.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Minimal ELF header for architecture preflight; never executed.
	h := make([]byte, 64)
	copy(h, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 3})
	binary.LittleEndian.PutUint16(h[16:], 2)
	binary.LittleEndian.PutUint16(h[18:], 183)
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint16(h[52:], 64)
	helper := filepath.Join(t.TempDir(), "linux-helper")
	if err := os.WriteFile(helper, h, 0o600); err != nil {
		t.Fatal(err)
	}
	p.cfg.Containers = &config.Containers{Engine: "docker", Baseline: "linux-base", CPU: 2, MemoryGB: 2, Helper: helper}
	p.checkIsolation = func(context.Context) (vm.SoftnetOptions, error) {
		policy, err := NetworkPolicy()
		return vm.SoftnetOptions{Binary: "/opt/softnet", Block: policy}, err
	}
	return p, r, provider.Spec{Name: name, Baseline: "base", CPU: 4, MemoryMB: 8192, Meta: provider.Metadata{ControllerID: "ctl-1", InstanceID: "pair"}}
}

func TestPairLifecycleAndRestart(t *testing.T) {
	p, r, spec := pairProvider(t)
	ctx := context.Background()
	if err := p.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(ctx, spec.Name, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.calls {
		if c[0] != "Start" {
			continue
		}
		a := strings.Join(c, " ")
		if !strings.Contains(a, "softnet-block=") || !strings.Contains(a, "@host") || strings.Contains(a, "share=") || strings.Contains(a, "input") {
			t.Fatalf("unsafe launch %v", c)
		}
	}
	owned, foreign, err := p.List(ctx)
	if err != nil || len(owned) != 1 || len(foreign) != 0 {
		t.Fatalf("logical pair list: %v %v %v", owned, foreign, err)
	}
	// A new provider process has only records/metadata, not saved process handles.
	restarted, err := New(p.name, p.cfg, p.controllerID, string(p.store), callRuntime{r})
	if err != nil {
		t.Fatal(err)
	}
	restarted.SetRecords(p.records)
	if err = restarted.Stop(ctx, spec.Name, time.Second); err != nil {
		t.Fatal(err)
	}
	delete(r.vms, spec.Name) // partial prior cleanup: companion still reserves capacity
	st, err := restarted.Status(ctx, spec.Name)
	if err != nil || !st.Exists || !st.Owned {
		t.Fatalf("companion not retained: %+v %v", st, err)
	}
	if err = restarted.Delete(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	st, err = restarted.Status(ctx, spec.Name)
	if err != nil || st.Exists {
		t.Fatalf("pair not deleted: %+v %v", st, err)
	}
}

func TestPairRejectsMissingRecordAndForeignMetadata(t *testing.T) {
	for _, kind := range []string{"record", "controller", "instance", "parent"} {
		t.Run(kind, func(t *testing.T) {
			p, r, spec := pairProvider(t)
			ctx := context.Background()
			if err := p.Create(ctx, spec); err != nil {
				t.Fatal(err)
			}
			if kind == "record" {
				_ = p.records.Remove("pair")
			} else {
				m, _ := p.readMeta(spec.Name + "-engine")
				switch kind {
				case "controller":
					m.ControllerID = "other"
				case "instance":
					m.InstanceID = "other"
				case "parent":
					m.ParentName = "bivouac-other"
				}
				data, _ := json.Marshal(m)
				_ = os.WriteFile(filepath.Join(p.vmDir(spec.Name+"-engine"), markerFile), data, 0o600)
			}
			r.calls = nil
			for _, err := range []error{p.Start(ctx, spec.Name, io.Discard), p.WaitReady(ctx, spec.Name), p.StopRunner(ctx, spec.Name), p.Stop(ctx, spec.Name, time.Second), p.Delete(ctx, spec.Name)} {
				if !errors.Is(err, provider.ErrNotOwned) {
					t.Fatalf("proof failure: %v", err)
				}
			}
			for _, c := range r.calls {
				if c[0] == "Stop" || c[0] == "Delete" || c[0] == "Start" || c[0] == "Exec" {
					t.Fatalf("touched unowned pair %v", c)
				}
			}
		})
	}
}

func TestIsolationFailureBeforeClone(t *testing.T) {
	p, r, spec := pairProvider(t)
	p.checkIsolation = func(context.Context) (vm.SoftnetOptions, error) {
		return vm.SoftnetOptions{}, errors.New("privilege unavailable")
	}
	if err := p.Create(context.Background(), spec); err == nil {
		t.Fatal("isolation failure accepted")
	}
	if len(r.calls) != 0 {
		t.Fatalf("preflight touched VM: %v", r.calls)
	}
}

type deleteFailure struct {
	*recorder
	name string
}

func (r deleteFailure) Run(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if args[0] == "Delete" && args[1] == r.name {
		return errors.New("delete failed")
	}
	return r.recorder.Run(ctx, args, in, out)
}

func TestPartialPairDeleteRetainsReservation(t *testing.T) {
	p, r, spec := pairProvider(t)
	ctx := context.Background()
	if err := p.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	p.rt = callRuntime{deleteFailure{r, spec.Name + "-engine"}}
	if err := p.Delete(ctx, spec.Name); err == nil {
		t.Fatal("delete failure hidden")
	}
	st, err := p.Status(ctx, spec.Name)
	if err != nil || !st.Exists {
		t.Fatalf("companion deletion not reserved: %+v %v", st, err)
	}
	p.rt = callRuntime{r}
	if err = p.Delete(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
}

func TestRelayProofAndTopologyDisable(t *testing.T) {
	p, r, spec := pairProvider(t)
	ctx := context.Background()
	if err := p.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(ctx, spec.Name, io.Discard); err != nil {
		t.Fatal(err)
	}
	policy, _ := NetworkPolicy()
	plan := RelayPlan{StatePath: p.records.Path(), Store: string(p.store), Name: spec.Name, InstanceID: "pair", ControllerID: p.controllerID, Engine: "docker", Policy: policy}
	if err := plan.verify(); err != nil {
		t.Fatal(err)
	}
	plan.Engine = "/personal/docker.sock"
	if plan.verify() == nil {
		t.Fatal("arbitrary endpoint accepted")
	}
	plan.Engine = "docker"
	_ = p.records.Remove("pair")
	if plan.verify() == nil {
		t.Fatal("missing durable record accepted")
	}
	p.cfg.Containers = nil
	r.calls = nil
	if err := p.Delete(ctx, spec.Name); !errors.Is(err, provider.ErrNotOwned) {
		t.Fatal("topology disable released pair")
	}
	if err := p.Stop(ctx, spec.Name+"-engine", time.Second); !errors.Is(err, provider.ErrNotOwned) {
		t.Fatal("topology disable touched companion")
	}
	owned, _, err := p.List(ctx)
	if err != nil || len(owned) != 0 {
		t.Fatal("orphan pair exposed to generic cleanup")
	}
}
