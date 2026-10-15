package appsandbox

import (
	"context"
	"errors"
	"testing"

	"github.com/GomerPiles/bivouac/internal/provider"
)

type fixtureGuest struct {
	ready, started, stopped int
	preflight               func() error
	forgotten               []string
}

func (g *fixtureGuest) Preflight(context.Context, Lease) error {
	if g.preflight != nil {
		return g.preflight()
	}
	return nil
}

func TestProviderLeavesNICAbsentUntilGuestConsolePreflight(t *testing.T) {
	p, _, n, g, r := providerFixture(t)
	booting := errors.New("setup or intended console logon incomplete")
	g.preflight = func() error {
		if n.attached {
			t.Fatal("network attached before console readiness")
		}
		return booting
	}
	if err := p.WaitReady(context.Background(), r.RunnerName); !errors.Is(err, booting) || n.attached || g.ready != 0 {
		t.Fatal("failed preflight admitted networking or runner bootstrap")
	}
	g.preflight = func() error {
		if n.attached {
			t.Fatal("network attached before console readiness")
		}
		return nil
	}
	if err := p.WaitReady(context.Background(), r.RunnerName); err != nil || !n.attached || g.ready != 1 {
		t.Fatal(err)
	}
}

func (g *fixtureGuest) Ready(context.Context, Lease) error               { g.ready++; return nil }
func (g *fixtureGuest) StartRunner(context.Context, Lease, []byte) error { g.started++; return nil }
func (g *fixtureGuest) StopRunner(context.Context, Lease) error          { g.stopped++; return nil }
func (*fixtureGuest) RunnerStatus(context.Context, Lease) (provider.RunnerStatus, error) {
	return provider.RunnerStatus{State: provider.RunnerListening}, nil
}
func (*fixtureGuest) CollectDiagnostics(context.Context, Lease, string) error { return nil }
func (g *fixtureGuest) Forget(name string) error {
	g.forgotten = append(g.forgotten, name)
	return nil
}
func providerFixture(t *testing.T) (*Provider, *Engine, *testNetwork, *fixtureGuest, CloneRecord) {
	t.Helper()
	e, _, n, r := engineFixture(t)
	g := &fixtureGuest{}
	p, err := New(Options{Name: "windows", Root: e.Root(), ControllerID: r.Meta.ControllerID, DiskGB: 80, GPU: true}, e, g)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Create(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return p, e, n, g, r
}
func TestProviderAdmitsJITOnlyAfterCurrentPolicyProof(t *testing.T) {
	p, _, n, g, r := providerFixture(t)
	ctx := context.Background()
	if err := p.StartRunner(ctx, r.RunnerName, []byte("synthetic")); err == nil || g.started != 0 {
		t.Fatal("JIT reached an unprepared VM")
	}
	if err := p.WaitReady(ctx, r.RunnerName); err != nil || g.ready != 1 {
		t.Fatal(err)
	}
	n.verifyErr = errors.New("native filter changed")
	if err := p.StartRunner(ctx, r.RunnerName, []byte("synthetic")); err == nil || g.started != 0 || !n.blocked {
		t.Fatal("JIT reached a weakened network")
	}
	if _, err := p.RunnerStatus(ctx, r.RunnerName); err == nil {
		t.Fatal("status silently accepted changed policy")
	} else {
		var transport provider.TransportFailure
		if errors.As(err, &transport) {
			t.Fatal("native policy failure was classified as guest transport")
		}
	}
}
func TestProviderCannotOperateAnotherProviderGuest(t *testing.T) {
	p, e, _, _, r := providerFixture(t)
	other, err := New(Options{Name: "other", Root: e.Root(), ControllerID: r.Meta.ControllerID, DiskGB: 80}, e, &fixtureGuest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Delete(context.Background(), r.RunnerName); !errors.Is(err, provider.ErrNotOwned) {
		t.Fatal(err)
	}
	owned, foreign, err := other.List(context.Background())
	if err != nil || len(owned) != 0 || len(foreign) != 1 {
		t.Fatal("cross-provider guest was claimed")
	}
	if _, err := p.Status(context.Background(), r.RunnerName); err != nil {
		t.Fatal(err)
	}
}
func TestGuardQuarantinesPolicyLossAndBlocksNewAdmissions(t *testing.T) {
	_, e, n, _, r := providerFixture(t)
	ctx := context.Background()
	if _, err := e.Prepare(ctx, r.RunnerName); err != nil {
		t.Fatal(err)
	}
	n.verifyErr = errors.New("host interface changed")
	if err := e.Guard(ctx); err == nil || !n.blocked {
		t.Fatal("independent guard failed to block")
	}
	record, err := e.records.Get(r.RunnerName)
	if err != nil || record.Phase != "quarantined" {
		t.Fatal("quarantine was not durable")
	}
	if err := e.Create(ctx, r); err == nil {
		t.Fatal("admission continued after policy failure")
	}
	if err := e.Delete(ctx, r.RunnerName); err != nil {
		t.Fatal(err)
	}
}
func TestProviderForgetsGuestTransportAfterConfirmedDeletion(t *testing.T) {
	p, _, n, g, r := providerFixture(t)
	ctx := context.Background()
	if err := p.WaitReady(ctx, r.RunnerName); err != nil {
		t.Fatal(err)
	}
	n.deleteErr = errors.New("network still in use")
	if err := p.Delete(ctx, r.RunnerName); err == nil || len(g.forgotten) != 0 {
		t.Fatal("transport state discarded before confirmed deletion")
	}
	n.deleteErr = nil
	if err := p.Delete(ctx, r.RunnerName); err != nil || len(g.forgotten) != 1 || g.forgotten[0] != r.RunnerName {
		t.Fatalf("transport state retained: %v %v", g.forgotten, err)
	}
}
