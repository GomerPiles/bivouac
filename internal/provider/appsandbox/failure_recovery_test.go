package appsandbox

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/GomerPiles/bivouac/internal/provider"
)

// Reopen the filesystem journal and rebuild the engine with fresh process
// state. Preserve the native objects: they outlive a controller or broker.
func restartFixture(t *testing.T, e *Engine, a *testAPI, n *testNetwork) *Engine {
	t.Helper()
	path := e.records.path
	if err := e.records.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := OpenRecords(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = records.Close() })
	a.root = records
	restarted, err := NewEngine(e.opts, a, n, records, e.checkBaseline)
	if err != nil {
		t.Fatal(err)
	}
	return restarted
}

func TestEngineRestartAfterAppliedMutationsLoseResponses(t *testing.T) {
	e, a, n, r := engineFixture(t)
	ctx := context.Background()
	e.api = &nativeAPIFault{NativeAPI: a, createAfter: true}
	if err := e.Create(ctx, r); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("create response: %v", err)
	}
	e = restartFixture(t, e, a, n)
	if _, err := e.Lookup(ctx, r.RunnerName); err != nil {
		t.Fatal(err)
	}
	if child, err := e.records.Child(r); err != nil || child != r {
		t.Fatal("restart did not bind native identity to prior intent")
	}
	if err := e.Create(ctx, r); err == nil {
		t.Fatal("ambiguous creation was dispatched twice")
	}
	e.api = &nativeAPIFault{NativeAPI: a, deleteAfter: true}
	if err := e.Delete(ctx, r.RunnerName); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("delete response: %v", err)
	}
	if _, err := e.records.Get(r.RunnerName); err != nil || a.vm.Name != "" {
		t.Fatal("applied deletion lost durable reservation")
	}
	e = restartFixture(t, e, a, n)
	if err := e.Delete(ctx, r.RunnerName); err != nil {
		t.Fatal(err)
	}
	if err := e.Delete(ctx, r.RunnerName); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(a.calls, []string{"create", "stop", "delete"}) {
		t.Fatalf("replayed native mutation: %v", a.calls)
	}
	if _, err := e.records.Get(r.RunnerName); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reservation survives confirmed cleanup")
	}
}

func TestEngineRestartRetainsPartialNetworkCleanupAndCapacity(t *testing.T) {
	e, a, n, r := engineFixture(t)
	ctx := context.Background()
	if err := e.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	e.net = &nativeNetworkFault{NativeNetwork: n, attachAfter: true, deleteBefore: true}
	if _, err := e.Prepare(ctx, r.RunnerName); err == nil || !n.attached || !n.blocked {
		t.Fatal("partial attachment was not blocked")
	}
	if err := e.Verify(ctx, r.RunnerName); err == nil {
		t.Fatal("partial attachment admitted ready")
	}
	e = restartFixture(t, e, a, n)
	if err := e.Guard(ctx); err == nil {
		t.Fatal("restart did not quarantine partial attachment")
	}
	e.net = &nativeNetworkFault{NativeNetwork: n, deleteBefore: true}
	if err := e.Delete(ctx, r.RunnerName); err == nil {
		t.Fatal("network cleanup fault was lost")
	}
	record, err := e.records.Get(r.RunnerName)
	if err != nil || record.Phase != "native_deleted" || record.Network == nil || a.vm.Name != "" || !n.attached {
		t.Fatal("partial cleanup lost its native-absent network reservation")
	}
	e = restartFixture(t, e, a, n)
	next, err := PlanClone(e.Root(), provider.Spec{Name: "bivouac-windows-5678abcd", Baseline: r.Template, CPU: r.CPU, MemoryMB: r.MemoryMB, Meta: provider.Metadata{ControllerID: r.Meta.ControllerID, InstanceID: "5678abcd", CreatedAt: r.Meta.CreatedAt}}, r.DiskGB, r.GPUMode)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Create(ctx, next); err == nil {
		t.Fatal("unresolved network cleanup released capacity")
	}
	if err = e.Delete(ctx, r.RunnerName); err != nil || n.attached {
		t.Fatalf("cleanup after restart: %v", err)
	}
	if !slices.Equal(a.calls, []string{"create", "stop", "delete"}) {
		t.Fatalf("repeated native deletion: %v", a.calls)
	}
	if err = e.Create(ctx, next); err != nil {
		t.Fatalf("confirmed cleanup did not release capacity: %v", err)
	}
}

func TestEngineGuardEnforcesPolicyWhileAppSandboxUnavailable(t *testing.T) {
	for _, policyLost := range []bool{false, true} {
		name := "policy-intact"
		if policyLost {
			name = "policy-lost"
		}
		t.Run(name, func(t *testing.T) {
			e, a, n, r := engineFixture(t)
			e.opts.MaxInstances = 2
			ctx := context.Background()
			if err := e.Create(ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Prepare(ctx, r.RunnerName); err != nil {
				t.Fatal(err)
			}
			n.calls = nil
			a.statusErr = errors.New("synthetic App Sandbox outage")
			if policyLost {
				n.verifyErr = errors.New("host interface changed")
			}
			if err := e.Guard(ctx); err == nil {
				t.Fatal("incomplete guard pass reported success")
			}
			if !slices.Contains(n.calls, "verify") {
				t.Fatal("guard skipped policy verification during the outage")
			}
			if n.blocked != policyLost || !a.vm.Running || slices.Contains(a.calls, "stop") {
				t.Fatalf("enforcement without native identity: blocked=%v calls=%v", n.blocked, a.calls)
			}
			a.statusErr = nil
			n.verifyErr = nil
			// A full successful pass clears an outage, never a policy failure.
			if err := e.Guard(ctx); err != nil && !policyLost {
				t.Fatal(err)
			}
			next, err := PlanClone(e.Root(), provider.Spec{Name: "bivouac-windows-5678abcd", Baseline: r.Template, CPU: r.CPU, MemoryMB: r.MemoryMB, Meta: provider.Metadata{ControllerID: r.Meta.ControllerID, InstanceID: "5678abcd", CreatedAt: r.Meta.CreatedAt}}, r.DiskGB, r.GPUMode)
			if err != nil {
				t.Fatal(err)
			}
			if err = e.Create(ctx, next); (err == nil) == policyLost {
				t.Fatalf("admission after recovery (policy lost %v): %v", policyLost, err)
			}
		})
	}
}

func TestEngineGuardFailedBlockStopsOnlyVerifiedOwnership(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		name := "owned"
		if foreign {
			name = "changed-native-identity"
		}
		t.Run(name, func(t *testing.T) {
			e, a, n, r := engineFixture(t)
			ctx := context.Background()
			if err := e.Create(ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Prepare(ctx, r.RunnerName); err != nil {
				t.Fatal(err)
			}
			e.net = &nativeNetworkFault{NativeNetwork: n, verifyBefore: true, blockBefore: true}
			if foreign {
				a.vm.DiskDirectory = e.Root()
			}
			if err := e.Guard(ctx); err == nil {
				t.Fatal("guard fault not reported")
			}
			if foreign {
				if !a.vm.Running || !slices.Equal(a.calls, []string{"create"}) {
					t.Fatal("guard stopped an identity it could not prove")
				}
				return
			}
			if a.vm.Running || !slices.Equal(a.calls, []string{"create", "stop"}) {
				t.Fatal("block failure did not stop the owned guest")
			}
			e = restartFixture(t, e, a, n)
			record, err := e.records.Get(r.RunnerName)
			if err != nil || record.Phase != "quarantined" {
				t.Fatal("quarantine did not survive restart")
			}
			if err = e.Start(ctx, r.RunnerName); err == nil || a.vm.Running {
				t.Fatal("restart resumed a stopped network binding")
			}
			if err = e.Delete(ctx, r.RunnerName); err != nil {
				t.Fatal(err)
			}
		})
	}
}
