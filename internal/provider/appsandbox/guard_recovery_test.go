package appsandbox

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/GomerPiles/bivouac/internal/netpolicy"
	"github.com/GomerPiles/bivouac/internal/provider"
)

// Model a changed host snapshot using the same prefix calculation as the
// native adapter, without changing this host's interfaces or creating a VM.
type changingHostNetwork struct {
	*testNetwork
	host []netip.Prefix
}

func (n *changingHostNetwork) Plan(ctx context.Context, c CloneRecord, all []EngineRecord) (NetworkPlan, error) {
	plan, err := n.testNetwork.Plan(ctx, c, all)
	if err != nil {
		return plan, err
	}
	plan.Blocked, plan.HostSnapshot, err = netpolicy.BlockedPrefixes(n.host)
	return plan, err
}
func (n *changingHostNetwork) Verify(ctx context.Context, r EngineRecord) error {
	if err := n.testNetwork.Verify(ctx, r); err != nil {
		return err
	}
	blocked, snapshot, err := netpolicy.BlockedPrefixes(n.host)
	if err != nil {
		return err
	}
	if snapshot != r.Network.HostSnapshot || !slices.Equal(blocked, r.Network.Blocked) {
		return errors.New("host interface policy changed; discard guest")
	}
	return nil
}

func recoveryClone(t *testing.T, e *Engine, r CloneRecord, id string) CloneRecord {
	t.Helper()
	next, err := PlanClone(e.Root(), provider.Spec{Name: "bivouac-windows-" + id, Baseline: r.Template, CPU: r.CPU, MemoryMB: r.MemoryMB, Meta: provider.Metadata{ControllerID: r.Meta.ControllerID, InstanceID: id, CreatedAt: r.Meta.CreatedAt}}, r.DiskGB, r.GPUMode)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func TestGuardRecoversAfterInterfaceChangeWithoutBrokerRestart(t *testing.T) {
	e, a, base, first := engineFixture(t)
	e.opts.MaxInstances = 2 // Admission assertions must not rely on capacity.
	n := &changingHostNetwork{testNetwork: base, host: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}}
	e.net = n
	ctx := context.Background()
	current := first
	changes := []struct {
		id   string
		host []netip.Prefix
	}{
		{"5678abcd", []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("198.51.100.1/24")}},
		{"abcdef12", []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}},
	}
	for _, change := range changes {
		if err := e.Create(ctx, current); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Prepare(ctx, current.RunnerName); err != nil {
			t.Fatal(err)
		}
		before, err := e.records.Get(current.RunnerName)
		if err != nil {
			t.Fatal(err)
		}
		previous := n.host
		n.host = change.host
		networkCalls := len(base.calls)
		if err := e.Guard(ctx); err == nil || !base.blocked {
			t.Fatal("changed host policy was not quarantined")
		}
		next := recoveryClone(t, e, current, change.id)
		calls := len(a.calls)
		if err := e.Create(ctx, next); err == nil || len(a.calls) != calls {
			t.Fatal("quarantine admitted another native mutation")
		}
		// Reverting host policy cannot reopen or rewrite the old guest's binding.
		n.host = previous
		if err := e.Guard(ctx); err == nil {
			t.Fatal("interface restoration cleared a retained quarantine")
		}
		after, err := e.records.Get(current.RunnerName)
		if err != nil || after.Phase != "quarantined" || after.Network.HostSnapshot != before.Network.HostSnapshot {
			t.Fatal("quarantined policy was repaired or lost")
		}
		if slices.Contains(base.calls[networkCalls:], "attach") || len(a.calls) != calls {
			t.Fatal("guard resumed a quarantined VM")
		}
		n.host = change.host
		if err := e.Delete(ctx, current.RunnerName); err != nil {
			t.Fatal(err)
		}
		if err := e.Create(ctx, next); err == nil {
			t.Fatal("cleanup bypassed the successful guard pass")
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := e.Guard(canceled); err == nil {
			t.Fatal("canceled pass reported healthy")
		}
		if err := e.Create(ctx, next); err == nil {
			t.Fatal("canceled pass cleared admission")
		}
		if err := e.Guard(ctx); err != nil {
			t.Fatal(err)
		}
		current = next
	}
	if err := e.Create(ctx, current); err != nil {
		t.Fatalf("broker still locked out after cleanup: %v", err)
	}
	if _, err := e.Prepare(ctx, current.RunnerName); err != nil {
		t.Fatal(err)
	}
	record, err := e.records.Get(current.RunnerName)
	_, snapshot, policyErr := netpolicy.BlockedPrefixes(n.host)
	if err != nil || policyErr != nil || record.Network.HostSnapshot != snapshot {
		t.Fatal("replacement reused the previous host policy")
	}
}

func TestGuardWaitsForQuarantinedNetworkCleanup(t *testing.T) {
	for _, phase := range []string{"quarantined-stopped", "quarantined-absent", "native_deleted", "network_deleted"} {
		t.Run(phase, func(t *testing.T) {
			e, a, n, r := engineFixture(t)
			e.opts.MaxInstances = 2
			ctx := context.Background()
			if err := e.Create(ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Prepare(ctx, r.RunnerName); err != nil {
				t.Fatal(err)
			}
			n.verifyErr = errors.New("host interface changed")
			if err := e.Guard(ctx); err == nil {
				t.Fatal("policy change not detected")
			}
			n.verifyErr = nil
			if err := e.Stop(ctx, r.RunnerName, 0); err != nil {
				t.Fatal(err)
			}
			if phase != "quarantined-stopped" {
				n.deleteErr = errors.New("synthetic network cleanup failure")
				if err := e.Delete(ctx, r.RunnerName); err == nil {
					t.Fatal("cleanup failure was not retained")
				}
				n.deleteErr = nil
				record, err := e.records.Get(r.RunnerName)
				if err != nil {
					t.Fatal(err)
				}
				if phase == "quarantined-absent" {
					record.Phase = "quarantined"
				} else {
					record.Phase = phase
					if phase == "network_deleted" {
						n.attached = false
					}
				}
				if err := e.records.Put(record); err != nil {
					t.Fatal(err)
				}
			}
			// Reconstruct the engine too: the protected record, not a process latch,
			// must prevent admission while a stopped/absent VM still needs cleanup.
			e = restartFixture(t, e, a, n)
			calls := len(a.calls)
			if err := e.Guard(ctx); err == nil {
				t.Fatal("unfinished network cleanup reported healthy")
			}
			next := recoveryClone(t, e, r, "5678abcd")
			if err := e.Create(ctx, next); err == nil || len(a.calls) != calls {
				t.Fatal("retained network cleanup admitted a new VM")
			}
			if err := e.Delete(ctx, r.RunnerName); err != nil {
				t.Fatal(err)
			}
			if err := e.Guard(ctx); err != nil {
				t.Fatal(err)
			}
			if err := e.Create(ctx, next); err != nil {
				t.Fatalf("cleanup did not recover admission: %v", err)
			}
		})
	}
}
