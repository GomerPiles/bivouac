//go:build windows

package vmhost

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/hcs"
	"github.com/GomerPiles/bivouac/internal/hostnet"
	"golang.org/x/sys/windows"
)

const fakeRuntimeID = "11111111-2222-3333-4444-555555555555"

type networkFault struct {
	calls        int
	once, sticky error
}

func (f *networkFault) next() error {
	f.calls++
	if f.once != nil {
		err := f.once
		f.once = nil
		return err
	}
	return f.sticky
}

type protection struct {
	beforeStart bool
	runtimeID   string
}

// fakeNetwork uses the fake HCS inventory for port lifetime and runtime proof.
// Faults and channels are configured before starting an operation, and inspected
// after it completes (or signals verifyEntered).
type fakeNetwork struct {
	t               *testing.T
	native          *fakeNative
	retained        [][]hostnet.Plan
	plans           []hostnet.Plan
	networks        map[string]hostnet.Plan
	portBeforeStart bool
	beforeRuntimeID string
	protections     []protection
	planErr         error
	portErr         error
	create          networkFault
	protect         networkFault
	verify          networkFault
	block           networkFault
	delete          networkFault
	verifyEntered   chan<- struct{}
	verifyRelease   <-chan struct{}
}

func attachNetwork(t *testing.T, h *Host, n *fakeNative) *fakeNetwork {
	t.Helper()
	f := &fakeNetwork{t: t, native: n, networks: map[string]hostnet.Plan{}}
	h.net = f
	return f
}

func networkFixture(t *testing.T) (*Host, *fakeNative, *fakeNetwork) {
	t.Helper()
	h, n := fixture(t)
	return h, n, attachNetwork(t, h, n)
}

func networkSpec() Spec {
	s := validSpec()
	s.Network = true
	return s
}

func (f *fakeNetwork) Plan(_ context.Context, guest string, retained []hostnet.Plan) (hostnet.Plan, error) {
	f.retained = append(f.retained, slices.Clone(retained))
	if f.planErr != nil {
		return hostnet.Plan{}, f.planErr
	}
	for i := 0; i < 4096; i++ {
		subnet := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 251, byte(i / 16), byte(i % 16 * 16)}), 28)
		overlaps := false
		for _, p := range retained {
			q, err := netip.ParsePrefix(p.Subnet)
			if err != nil {
				return hostnet.Plan{}, err
			}
			overlaps = overlaps || subnet.Overlaps(q)
		}
		if overlaps {
			continue
		}
		id := len(f.plans) * 3
		p := hostnet.Plan{
			NetworkID:       fmt.Sprintf("aaaaaaaa-1111-4111-8111-%012x", id+1),
			EndpointID:      fmt.Sprintf("aaaaaaaa-1111-4111-8111-%012x", id+2),
			FirewallCreator: fmt.Sprintf("aaaaaaaa-1111-4111-8111-%012x", id+3),
			NetworkName:     guest + "-net", EndpointName: guest + "-ep", Layer: guest,
			Subnet: subnet.String(), Gateway: subnet.Addr().Next().String(), Address: subnet.Addr().Next().Next().String(),
			MAC: hostnet.MAC(guest), Blocked: []string{"10.0.0.0/8"}, HostSnapshot: strings.Repeat("a", 64),
		}
		if err := p.Validate(guest); err != nil {
			f.t.Errorf("fake generated invalid plan: %v", err)
		}
		f.plans = append(f.plans, p)
		return p, nil
	}
	return hostnet.Plan{}, errors.New("fake subnet pool exhausted")
}

func (f *fakeNetwork) Create(_ context.Context, p hostnet.Plan, guest string) error {
	var r record
	if err := f.native.host.read(recordName(guest), &r); err != nil || r.Phase != phaseIntent || !reflect.DeepEqual(r.Network, &p) {
		f.t.Error("network create preceded exact journalled intent", err)
	}
	// A failed native create may leave partial state that still needs deletion.
	f.networks[guest] = p
	return f.create.next()
}

func (f *fakeNetwork) Port(_ context.Context, p hostnet.Plan) (bool, bool, error) {
	f.native.mu.Lock()
	defer f.native.mu.Unlock()
	s := f.native.systems[p.Layer]
	return s != nil, s != nil && (f.portBeforeStart || s.props.State == hcs.StateRunning), f.portErr
}

func (f *fakeNetwork) Protect(_ context.Context, p hostnet.Plan, guest, runtimeID string) (hostnet.Plan, error) {
	f.native.mu.Lock()
	defer f.native.mu.Unlock()
	s := f.native.systems[guest]
	if s == nil {
		return p, errors.New("fake port absent")
	}
	before := s.props.State != hcs.StateRunning
	f.protections = append(f.protections, protection{beforeStart: before, runtimeID: runtimeID})
	if err := f.protect.next(); err != nil {
		return p, err
	}
	if before && !f.portBeforeStart {
		return p, errors.New("fake port disconnected")
	}
	id := s.props.RuntimeID
	if before {
		id = fakeRuntimeID
		if f.beforeRuntimeID != "" {
			id = f.beforeRuntimeID
		}
	}
	if runtimeID != "" && !strings.EqualFold(strings.Trim(runtimeID, "{}"), strings.Trim(id, "{}")) {
		return p, hostnet.ErrForeign
	}
	p.VMRuntimeID = id
	f.networks[guest] = p
	return p, p.Validate(guest)
}

func (f *fakeNetwork) Verify(ctx context.Context, p hostnet.Plan, guest string) error {
	err := f.verify.next()
	if f.verifyEntered != nil {
		select {
		case f.verifyEntered <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.verifyRelease != nil {
		select {
		case <-f.verifyRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	if err := p.Validate(guest); err != nil {
		return err
	}
	f.native.mu.Lock()
	defer f.native.mu.Unlock()
	s := f.native.systems[guest]
	if s == nil || s.props.State != hcs.StateRunning || p.VMRuntimeID != s.props.RuntimeID {
		return hostnet.ErrForeign
	}
	return nil
}

func (f *fakeNetwork) Block(_ context.Context, _ hostnet.Plan) error { return f.block.next() }

func (f *fakeNetwork) Delete(_ context.Context, p hostnet.Plan, guest string) error {
	f.native.mu.Lock()
	_, exists := f.native.systems[guest]
	f.native.mu.Unlock()
	if exists {
		f.t.Error("network deleted before HCS absence")
	}
	if err := p.Validate(guest); err != nil {
		f.t.Error("deleting invalid plan", err)
	}
	if err := f.delete.next(); err != nil {
		return err
	}
	delete(f.networks, guest)
	return nil
}

func createNetworkGuest(t *testing.T, h *Host) *Guest {
	t.Helper()
	g, err := h.Create(t.Context(), networkSpec())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func requireNetworkGone(t *testing.T, h *Host, n *fakeNative, f *fakeNetwork) {
	t.Helper()
	if len(n.systems) != 0 || len(f.networks) != 0 || len(entries(t, h)) != 0 || f.delete.calls == 0 {
		t.Fatal("guest, network, storage or journal survived cleanup")
	}
}

func TestNetworkCreateJournalsPlanBeforeMutationsAndCommitsAdapter(t *testing.T) {
	h, n, f := networkFixture(t)
	mutations := 0
	n.beforeMutation = func() {
		mutations++
		var r record
		if err := h.read(recordName(networkSpec().Name), &r); err != nil || len(f.plans) != 1 || !reflect.DeepEqual(r.Network, &f.plans[0]) {
			t.Error("native mutation preceded exact journalled plan", err)
		}
		if mutations <= 5 && r.Phase != phaseIntent { // disk, state, three grants
			t.Error("storage mutation preceded intent")
		}
	}
	g := createNetworkGuest(t, h)
	if mutations != 6 || f.create.calls != 1 || f.verify.calls != 1 || g.Network == nil || g.Network.VMRuntimeID != g.RuntimeID {
		t.Fatal("network creation or commitment missing")
	}
	p := *g.Network
	adapters := n.lastDocument.VirtualMachine.Devices.NetworkAdapters
	if len(adapters) != 1 || adapters[p.EndpointID].EndpointID != p.EndpointID || adapters[p.EndpointID].MacAddress != p.MAC {
		t.Fatal("creation document does not name exactly the planned adapter", adapters)
	}
	var r record
	if err := h.read(recordName(g.Name), &r); err != nil || !reflect.DeepEqual(r.Network, g.Network) || r.RuntimeID != g.RuntimeID {
		t.Fatal("committed network not journalled", err)
	}
	if err := h.VerifyNetwork(t.Context(), g); err != nil || f.verify.calls != 2 {
		t.Fatal("network reproof failed", err)
	}
	if err := h.BlockNetwork(t.Context(), g); err != nil || f.block.calls != 1 {
		t.Fatal("network blocking failed", err)
	}
	if err := h.Destroy(t.Context(), g); err != nil {
		t.Fatal(err)
	}
	requireNetworkGone(t, h, n, f)
}

func TestNetworkProtectBeforeStart(t *testing.T) {
	h, _, f := networkFixture(t)
	f.portBeforeStart = true
	g := createNetworkGuest(t, h)
	if !g.Timings.ProtectedBeforeStart || len(f.protections) != 1 || !f.protections[0].beforeStart || f.protections[0].runtimeID != "" {
		t.Fatal("protection did not precede start", f.protections)
	}
}

func TestNetworkProtectAfterStart(t *testing.T) {
	h, _, f := networkFixture(t)
	g := createNetworkGuest(t, h)
	if g.Timings.ProtectedBeforeStart || len(f.protections) != 1 || f.protections[0].beforeStart || f.protections[0].runtimeID != g.RuntimeID {
		t.Fatal("protection did not follow start with the runtime ID", f.protections)
	}
}

func TestNetworkPrestartRuntimeMismatchTearsDown(t *testing.T) {
	h, n, f := networkFixture(t)
	f.portBeforeStart = true
	f.beforeRuntimeID = "99999999-2222-4333-8444-555555555555"
	if _, err := h.Create(t.Context(), networkSpec()); !errors.Is(err, ErrForeign) {
		t.Fatal("runtime mismatch accepted", err)
	}
	requireNetworkGone(t, h, n, f)
}

func TestNetworkCreateFailuresTearDown(t *testing.T) {
	for _, stage := range []string{"create", "port", "protect-before", "protect-after", "verify"} {
		t.Run(stage, func(t *testing.T) {
			h, n, f := networkFixture(t)
			fault := errors.New("injected network failure")
			switch stage {
			case "create":
				f.create.once = fault
			case "port":
				f.portErr = fault
			case "protect-before":
				f.portBeforeStart = true
				f.protect.once = fault
			case "protect-after":
				f.protect.once = fault
			case "verify":
				f.verify.once = fault
			}
			if _, err := h.Create(t.Context(), networkSpec()); !errors.Is(err, fault) {
				t.Fatal("network failure not returned", err)
			}
			if stage == "create" && n.lastDocument.VirtualMachine != nil {
				t.Fatal("HCS create dispatched after network create failed")
			}
			requireNetworkGone(t, h, n, f)
		})
	}
}

func TestNetworkDestroyWaitsForAbsenceAndRetriesDelete(t *testing.T) {
	h, n, f := networkFixture(t)
	g := createNetworkGuest(t, h)
	n.lingers = 2
	f.delete.once = errors.New("transient delete failure")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := h.Destroy(ctx, g); err != nil || f.delete.calls != 2 || n.lingers != 0 {
		t.Fatal("delete did not wait and retry", err, f.delete.calls)
	}
	requireNetworkGone(t, h, n, f)
}

func TestNetworkForeignDeleteRetainsDeletingRecord(t *testing.T) {
	h, n, f := networkFixture(t)
	g := createNetworkGuest(t, h)
	f.delete.sticky = hostnet.ErrForeign
	if err := h.Destroy(t.Context(), g); !errors.Is(err, hostnet.ErrForeign) || f.delete.calls != 1 || len(n.systems) != 0 {
		t.Fatal("foreign deletion was retried or accepted", err)
	}
	var r record
	if err := h.read(recordName(g.Name), &r); err != nil || r.Phase != phaseDeleting || !reflect.DeepEqual(r.Network, g.Network) {
		t.Fatal("foreign network did not retain deleting record", err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, g.Name, diskFile)); err != nil {
		t.Fatal("retained storage removed", err)
	}
}

func TestNetworkRecoverDeletesAfterAbsence(t *testing.T) {
	h, n, f := networkFixture(t)
	g := createNetworkGuest(t, h)
	g.system.Close()
	n.lingers = 2
	if err := h.Recover(t.Context()); err != nil || n.terminateCalls != 1 {
		t.Fatal("network recovery failed", err)
	}
	requireNetworkGone(t, h, n, f)
}

func TestNetworkRecoverWithoutBackendRetainsRecord(t *testing.T) {
	h, n, f := networkFixture(t)
	g := createNetworkGuest(t, h)
	g.system.Close()
	h.net = nil
	if err := h.Recover(t.Context()); err == nil || len(n.systems) != 0 || f.delete.calls != 0 {
		t.Fatal("recovery without network backend succeeded", err)
	}
	var r record
	if err := h.read(recordName(g.Name), &r); err != nil || r.Phase != phaseDeleting || !reflect.DeepEqual(r.Network, g.Network) {
		t.Fatal("network recovery lost record", err)
	}
}

func TestNetworkPlanReceivesAllRetainedPlans(t *testing.T) {
	h, _, f := networkFixture(t)
	first := createNetworkGuest(t, h)
	spec := networkSpec()
	spec.Name = "bivouac-second"
	second, err := h.Create(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.retained) != 2 || len(f.retained[0]) != 0 || !reflect.DeepEqual(f.retained[1], []hostnet.Plan{*first.Network}) || first.Network.Subnet == second.Network.Subnet {
		t.Fatal("retained plan omitted or subnet reused", f.retained)
	}
}

func TestNetworkWithoutBackendRefusedBeforeJournal(t *testing.T) {
	for _, backendErr := range []error{nil, errors.New("backend unavailable")} {
		h, n := fixture(t)
		h.netErr = backendErr
		g, err := h.Create(t.Context(), networkSpec())
		if err == nil || g != nil || (backendErr != nil && !errors.Is(err, backendErr)) || len(entries(t, h)) != 0 || n.lastDocument.VirtualMachine != nil {
			t.Fatal("missing network backend accepted or journalled", err)
		}
	}
}

func TestNetworkPlanningFailuresPrecedeJournal(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		h, n, f := networkFixture(t)
		f.planErr = errors.New("planning failed")
		if corrupt {
			if err := os.WriteFile(filepath.Join(h.dir, "bivouac-retained.json"), []byte("invalid"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		before := entries(t, h)
		if _, err := h.Create(t.Context(), networkSpec()); err == nil || !reflect.DeepEqual(before, entries(t, h)) || n.lastDocument.VirtualMachine != nil {
			t.Fatal("failed planning changed journal or native state", err)
		}
		if corrupt && len(f.retained) != 0 {
			t.Fatal("planning proceeded with unreadable retained intent")
		}
	}
}

func TestNetworkHCSCreateFailureCleansUpOrRetainsUnknownOutcome(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprintf("unknown=%t", unknown), func(t *testing.T) {
			h, n, f := networkFixture(t)
			code := uint32(windows.ERROR_ACCESS_DENIED)
			if unknown {
				code = uint32(windows.HCS_E_OPERATION_TIMEOUT)
			}
			n.createErr = &hcs.Error{Op: "HcsCreateComputeSystem", Code: code}
			if _, err := h.Create(t.Context(), networkSpec()); err == nil || hcs.OutcomeUnknown(err) != unknown {
				t.Fatal("create outcome misclassified", err)
			}
			if unknown {
				var r record
				if err := h.read(recordName(networkSpec().Name), &r); err != nil || r.Phase != phaseDispatched || !reflect.DeepEqual(r.Network, &f.plans[0]) || f.delete.calls != 0 {
					t.Fatal("unknown outcome lost network intent", err)
				}
				n.createErr = nil
				if err := h.Recover(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			requireNetworkGone(t, h, n, f)
		})
	}
}

func TestNetworkCreateFailureRetainsForeignCleanup(t *testing.T) {
	h, n, f := networkFixture(t)
	f.create.once = errors.New("create partially failed")
	f.delete.sticky = hostnet.ErrForeign
	if _, err := h.Create(t.Context(), networkSpec()); !errors.Is(err, hostnet.ErrForeign) || len(n.systems) != 0 || n.lastDocument.VirtualMachine != nil || f.delete.calls != 1 {
		t.Fatal("partial network cleanup did not retain foreign state", err)
	}
	var r record
	if err := h.read(recordName(networkSpec().Name), &r); err != nil || r.Phase != phaseIntent || !reflect.DeepEqual(r.Network, &f.plans[0]) {
		t.Fatal("partial network failure lost intent", err)
	}
	f.delete.sticky = nil
	if err := h.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireNetworkGone(t, h, n, f)
}

func TestNetworkVerifyFailureRetainsGuestWhenTerminationFails(t *testing.T) {
	h, n, f := networkFixture(t)
	verifyErr := errors.New("policy verification failed")
	terminateErr := errors.New("termination unavailable")
	f.verify.once, n.terminateErr = verifyErr, terminateErr
	if _, err := h.Create(t.Context(), networkSpec()); !errors.Is(err, verifyErr) || !errors.Is(err, terminateErr) {
		t.Fatal("create lost the verification or cleanup failure", err)
	}
	var r record
	if err := h.read(recordName(networkSpec().Name), &r); err != nil || r.Phase != phaseCreated || r.Network == nil || r.Network.VMRuntimeID == "" {
		t.Fatal("failed termination lost committed network journal", err)
	}
	if s := n.systems[r.Spec.Name]; s == nil || s.props.State != hcs.StateRunning || f.delete.calls != 0 {
		t.Fatal("failed termination deleted a live guest's network")
	}
	n.terminateErr = nil
	if err := h.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireNetworkGone(t, h, n, f)
}

func TestNetworkDeleteCancellationRetainsRecord(t *testing.T) {
	h, n, f := networkFixture(t)
	g := createNetworkGuest(t, h)
	f.delete.sticky = errors.New("delete unavailable")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := h.Destroy(ctx, g); !errors.Is(err, f.delete.sticky) || len(n.systems) != 0 || f.delete.calls != 1 {
		t.Fatal("delete cancellation not retained", err)
	}
	var r record
	if err := h.read(recordName(g.Name), &r); err != nil || r.Phase != phaseDeleting {
		t.Fatal("canceled cleanup lost journal", err)
	}
}

func TestNonNetworkGuestSkipsNetworkOperations(t *testing.T) {
	h, _, f := networkFixture(t)
	g, err := h.Create(t.Context(), validSpec())
	if err != nil {
		t.Fatal(err)
	}
	if g.Network != nil || h.VerifyNetwork(t.Context(), g) != nil || h.BlockNetwork(t.Context(), g) != nil || h.Destroy(t.Context(), g) != nil {
		t.Fatal("non-network guest lifecycle failed")
	}
	if len(f.retained) != 0 || f.create.calls+f.protect.calls+f.verify.calls+f.block.calls+f.delete.calls != 0 {
		t.Fatal("non-network guest used network backend")
	}
}

func TestDurationsIncludesNetworkAndProtectMilliseconds(t *testing.T) {
	got := durations(Timings{Network: 2500 * time.Microsecond, Protect: 7500 * time.Microsecond})
	if got["network"] != 2 || got["protect"] != 7 || len(got) != 8 {
		t.Fatal("missing network timing milliseconds", got)
	}
}
