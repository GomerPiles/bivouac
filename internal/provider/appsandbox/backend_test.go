package appsandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/provider"
)

type testAPI struct {
	vm        VM
	root      *Records
	record    CloneRecord
	createErr error
	deleteErr error
	statusErr error
	calls     []string
}

func (a *testAPI) CreateClone(_ context.Context, r CloneRecord, _ string, password string) error {
	a.calls = append(a.calls, "create")
	prior, err := a.root.Get(r.RunnerName)
	if err != nil || !prior.Attempted || prior.Phase != "creating" {
		return errors.New("missing prior intent")
	}
	if parent, err := a.root.Parent(r); err != nil || parent != r || len(password) < 24 {
		return errors.New("missing prior parent or password")
	}
	a.record = r
	a.vm = VM{Name: r.NativeName, DiskDirectory: r.StorageParent, OSType: "Windows", CPUCores: r.CPU, RAMMB: r.MemoryMB, HDDGB: r.DiskGB, GPUMode: r.GPUMode, Running: true, InstallComplete: true, AgentOnline: true}
	if err := a.root.root.Mkdir(filepath.Join(r.Meta.InstanceID, r.NativeName), 0o700); err != nil {
		return err
	}
	return a.createErr
}
func (a *testAPI) VMCommand(_ context.Context, _ string, action string) error {
	a.calls = append(a.calls, action)
	switch action {
	case "start":
		a.vm.Running = true
	case "stop", "shutdown":
		a.vm.Running = false
	case "delete":
		if a.deleteErr != nil {
			return a.deleteErr
		}
		child := filepath.Join(a.record.Meta.InstanceID, a.record.NativeName)
		if err := a.root.root.Remove(filepath.Join(child, ownerMarker)); err != nil {
			return err
		}
		if err := a.root.root.Remove(child); err != nil {
			return err
		}
		a.vm = VM{}
	}
	return nil
}
func (a *testAPI) Status(_ context.Context, name string) (VM, error) {
	if a.statusErr != nil {
		return VM{}, a.statusErr
	}
	if a.vm.Name == "" || a.vm.Name != name {
		return VM{}, ErrNotFound
	}
	return a.vm, nil
}
func (a *testAPI) SSHInfo(context.Context, string) (SSH, error) {
	return SSH{Host: "127.0.0.1", Port: 2222, User: "ciuser", State: 4, Enabled: true, KeyDeployed: true}, nil
}
func (a *testAPI) List(context.Context) ([]VM, error) {
	if a.vm.Name == "" {
		return nil, nil
	}
	return []VM{a.vm}, nil
}

type testNetwork struct {
	attached  bool
	blocked   bool
	verifyErr error
	deleteErr error
	calls     []string
}

func (n *testNetwork) Plan(context.Context, CloneRecord, []EngineRecord) (NetworkPlan, error) {
	return NetworkPlan{NetworkID: "network", EndpointID: "endpoint", Address: "10.250.0.2", Gateway: "10.250.0.1", Subnet: "10.250.0.0/28"}, nil
}
func (n *testNetwork) Attach(context.Context, EngineRecord) error {
	n.attached = true
	n.calls = append(n.calls, "attach")
	return nil
}
func (n *testNetwork) Verify(context.Context, EngineRecord) error {
	n.calls = append(n.calls, "verify")
	return n.verifyErr
}
func (n *testNetwork) Block(context.Context, EngineRecord) error {
	n.blocked = true
	n.calls = append(n.calls, "block")
	return nil
}
func (n *testNetwork) Delete(context.Context, EngineRecord) error {
	n.calls = append(n.calls, "delete")
	if n.deleteErr != nil {
		return n.deleteErr
	}
	n.attached = false
	return nil
}

func engineFixture(t *testing.T) (*Engine, *testAPI, *testNetwork, CloneRecord) {
	t.Helper()
	root := t.TempDir()
	store, err := OpenRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	r, err := PlanClone(root, provider.Spec{Name: "bivouac-windows-1234abcd", Baseline: "test-template", CPU: 4, MemoryMB: 8192, Meta: provider.Metadata{ControllerID: "test-controller", InstanceID: "1234abcd", CreatedAt: "2026-01-01T00:00:00Z"}}, 80, 1)
	if err != nil {
		t.Fatal(err)
	}
	a := &testAPI{root: store}
	n := &testNetwork{}
	e, err := NewEngine(EngineOptions{ControllerID: r.Meta.ControllerID, Baseline: r.Template, User: "ciuser", MaxCPU: 4, MaxMemoryMB: 8192, MaxDiskGB: 80}, a, n, store, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return e, a, n, r
}
func TestEngineCreatesFromDurableIntentAndRejectsRetry(t *testing.T) {
	e, a, _, r := engineFixture(t)
	ctx := context.Background()
	if err := e.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := e.Create(ctx, r); err == nil {
		t.Fatal("blind create retry accepted")
	}
	if len(a.calls) != 1 {
		t.Fatalf("creation calls: %v", a.calls)
	}
	l, err := e.Lookup(ctx, r.RunnerName)
	if err != nil || l.Record != r || !l.VM.Running {
		t.Fatalf("lookup: %#v %v", l, err)
	}
}
func TestEngineRecoversMarkerAfterUnknownCreateResponse(t *testing.T) {
	e, a, _, r := engineFixture(t)
	ctx := context.Background()
	a.createErr = ErrOutcomeUnknown
	if err := e.Create(ctx, r); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	if _, err := e.records.Child(r); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("child marker appeared before accepted identity")
	}
	if _, err := e.Lookup(ctx, r.RunnerName); err != nil {
		t.Fatal(err)
	}
	if err := e.Delete(ctx, r.RunnerName); err != nil {
		t.Fatal(err)
	}
	if _, err := e.records.Get(r.RunnerName); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cleanup record survives")
	}
}
func TestEngineRefusesForeignMetadataAndMarkers(t *testing.T) {
	for _, change := range []string{"native", "parent", "child", "controller"} {
		t.Run(change, func(t *testing.T) {
			e, a, _, r := engineFixture(t)
			ctx := context.Background()
			if err := e.Create(ctx, r); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "native":
				a.vm.DiskDirectory = filepath.Dir(r.StorageParent)
			case "parent":
				if err := e.records.root.Remove(filepath.Join(r.Meta.InstanceID, ownerMarker)); err != nil {
					t.Fatal(err)
				}
			case "child":
				if err := e.records.root.Remove(filepath.Join(r.Meta.InstanceID, r.NativeName, ownerMarker)); err != nil {
					t.Fatal(err)
				}
			case "controller":
				e.opts.ControllerID = "other-controller"
			}
			if err := e.Delete(ctx, r.RunnerName); !errors.Is(err, provider.ErrNotOwned) {
				t.Fatalf("unsafe delete: %v", err)
			}
			if len(a.calls) != 1 {
				t.Fatalf("mutated foreign guest: %v", a.calls)
			}
		})
	}
}
func TestEngineRetainsNetworkCleanupReservation(t *testing.T) {
	e, a, n, r := engineFixture(t)
	ctx := context.Background()
	if err := e.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Prepare(ctx, r.RunnerName); err != nil {
		t.Fatal(err)
	}
	n.deleteErr = errors.New("network still in use")
	if err := e.Delete(ctx, r.RunnerName); err == nil {
		t.Fatal("lost failed cleanup")
	}
	if a.vm.Name != "" {
		t.Fatal("native guest survives")
	}
	retained, err := e.records.Get(r.RunnerName)
	if err != nil || retained.Phase != "native_deleted" {
		t.Fatalf("reservation: %v %v", retained, err)
	}
	n.deleteErr = nil
	if err := e.Delete(ctx, r.RunnerName); err != nil {
		t.Fatal(err)
	}
	if _, err := e.records.Get(r.RunnerName); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reservation not released")
	}
}
func TestEngineBlocksOnWeakenedPolicyAndDoesNotRepair(t *testing.T) {
	e, _, n, r := engineFixture(t)
	ctx := context.Background()
	if err := e.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Prepare(ctx, r.RunnerName); err != nil {
		t.Fatal(err)
	}
	n.verifyErr = errors.New("host interface changed")
	if err := e.Verify(ctx, r.RunnerName); err == nil || !n.blocked {
		t.Fatal("policy loss not blocked")
	}
	if len(n.calls) != 4 || n.calls[3] != "block" {
		t.Fatalf("unexpected repair: %v", n.calls)
	}
}
func TestEngineKeepsRecordAfterUnknownNativeDeletion(t *testing.T) {
	e, a, _, r := engineFixture(t)
	ctx := context.Background()
	if err := e.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	a.deleteErr = ErrOutcomeUnknown
	if err := e.Delete(ctx, r.RunnerName); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	if _, err := e.records.Get(r.RunnerName); err != nil {
		t.Fatal("record lost")
	}
}

// Each case leaves the journal as a crash at one point of creation or
// deletion would. Cleanup must finish without claiming a live instance.
func TestEngineFinishesInterruptedParentCleanup(t *testing.T) {
	for _, crash := range []string{"marker-removed", "parent-removed", "native-deleted-marker-removed", "intent-before-marker", "intent-temporary-marker"} {
		t.Run(crash, func(t *testing.T) {
			e, a, _, r := engineFixture(t)
			ctx := context.Background()
			parent := r.Meta.InstanceID
			if strings.HasPrefix(crash, "intent") {
				if err := e.records.Put(EngineRecord{Clone: r, Phase: "intent"}); err != nil {
					t.Fatal(err)
				}
				if err := e.records.root.Mkdir(parent, 0o700); err != nil {
					t.Fatal(err)
				}
				if crash == "intent-temporary-marker" {
					if err := e.records.root.WriteFile(filepath.Join(parent, ownerMarker+".new"), []byte("{"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				if err := e.Create(ctx, r); err != nil {
					t.Fatal(err)
				}
				if err := a.VMCommand(ctx, r.NativeName, "delete"); err != nil {
					t.Fatal(err)
				}
				phase := "network_deleted"
				if crash == "native-deleted-marker-removed" {
					phase = "native_deleted"
				}
				if err := e.records.Put(EngineRecord{Clone: r, Phase: phase, Attempted: true}); err != nil {
					t.Fatal(err)
				}
				if err := e.records.root.Remove(filepath.Join(parent, ownerMarker)); err != nil {
					t.Fatal(err)
				}
				if crash == "parent-removed" {
					if err := e.records.root.Remove(parent); err != nil {
						t.Fatal(err)
					}
				}
			}
			owned, foreign, err := e.List(ctx)
			if err != nil || len(owned) != 1 || len(foreign) != 0 {
				t.Fatalf("inventory after interrupted cleanup: %v %v %v", owned, foreign, err)
			}
			if err := e.Delete(ctx, r.RunnerName); err != nil {
				t.Fatal(err)
			}
			if _, err := e.records.Get(r.RunnerName); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("record survives cleanup")
			}
			if exists, err := e.records.ParentExists(r); err != nil || exists {
				t.Fatal("broker parent survives cleanup")
			}
		})
	}
}

func TestEngineKeepsUnmarkedParentWithUnknownContents(t *testing.T) {
	e, a, _, r := engineFixture(t)
	ctx := context.Background()
	if err := e.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := a.VMCommand(ctx, r.NativeName, "delete"); err != nil {
		t.Fatal(err)
	}
	if err := e.records.Put(EngineRecord{Clone: r, Phase: "network_deleted", Attempted: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.records.root.Remove(filepath.Join(r.Meta.InstanceID, ownerMarker)); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(r.Meta.InstanceID, "unknown.vhdx")
	if err := e.records.root.WriteFile(unknown, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Delete(ctx, r.RunnerName); err == nil {
		t.Fatal("non-empty unmarked parent removed")
	}
	if _, err := e.records.root.Stat(unknown); err != nil {
		t.Fatal("unknown file discarded")
	}
	if _, err := e.records.Get(r.RunnerName); err != nil {
		t.Fatal("reservation released with storage remaining")
	}
}

func TestEngineCreateRefusesExistingParent(t *testing.T) {
	e, a, _, r := engineFixture(t)
	if err := e.records.root.Mkdir(r.Meta.InstanceID, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := e.Create(context.Background(), r); err == nil {
		t.Fatal("creation adopted a pre-existing parent")
	}
	if _, err := e.records.Get(r.RunnerName); !errors.Is(err, os.ErrNotExist) || len(a.calls) != 0 {
		t.Fatal("intent recorded for a parent the broker did not create")
	}
}

func TestEngineListReportsUnprovableRecordWithoutFailing(t *testing.T) {
	e, a, _, r := engineFixture(t)
	ctx := context.Background()
	if err := e.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	a.vm.DiskDirectory = e.Root()
	owned, foreign, err := e.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 0 || len(foreign) != 1 || foreign[0].Name != r.RunnerName || !foreign[0].Prefixed || !foreign[0].Running {
		t.Fatalf("unprovable record: %v %v", owned, foreign)
	}
}
