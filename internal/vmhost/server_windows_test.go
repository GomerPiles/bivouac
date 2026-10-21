//go:build windows

package vmhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/hostnet"
	"github.com/GomerPiles/bivouac/internal/winguest"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const (
	alice = "S-1-5-21-1-2-3-1001"
	bob   = "S-1-5-21-1-2-3-1002"
	eve   = "S-1-5-21-9-9-9-1003"
)

func serverFixture(t *testing.T) (*Server, *fakeNative) {
	t.Helper()
	h, n := fixture(t)
	cfg := Config{Root: h.dir, Controller: "test", Accounts: []string{alice, bob}, Images: map[string]string{"win": `C:\Images\prepared.vhdx`}, MaxInstances: 2, MaxCPU: 8, MaxMemoryMB: 16384}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return NewServer(h, cfg), n
}

func call(t *testing.T, s *Server, sid string, req any) Response {
	t.Helper()
	s.identify = func(net.Conn) (string, error) { return sid, nil }
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go s.handle(server)
	go func() { _ = json.NewEncoder(client).Encode(req) }()
	var resp Response
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func createReq(name string) Request {
	return Request{Op: "create", Create: &CreateRequest{Name: name, Image: "win", CPU: 2, MemoryMB: 4096, GPU: true, Services: []string{winguest.AgentService, winguest.SSHService}}}
}

func TestUnlistedAccountsAreRefusedBeforeAnyWork(t *testing.T) {
	s, n := serverFixture(t)
	for _, req := range []Request{createReq("bivouac-a"), {Op: "info"}, {Op: "list"}} {
		if resp := call(t, s, eve, req); resp.Code != CodeRefused {
			t.Fatal("unlisted account served", req.Op, resp)
		}
	}
	if len(n.created) != 0 {
		t.Fatal("unlisted account reached HCS")
	}
}

func TestCreateMapsImageNamesAndGrantsOnlyTheCaller(t *testing.T) {
	s, _ := serverFixture(t)
	resp := call(t, s, alice, createReq("bivouac-a"))
	if resp.Code != "" || resp.Guest == nil || resp.Guest.RuntimeID == "" || resp.Guest.State != StateRunning {
		t.Fatal("create failed", resp)
	}
	var r record
	if err := s.host.read(recordName("bivouac-a"), &r); err != nil {
		t.Fatal(err)
	}
	if r.Spec.Image != `C:\Images\prepared.vhdx` || len(r.Spec.Services) != 2 {
		t.Fatal("image or services not taken from the VM host's config", r.Spec)
	}
	for _, service := range r.Spec.Services {
		if len(service.Connect) != 1 || service.Connect[0] != alice || len(service.Bind) != 0 {
			t.Fatal("HvSocket access not limited to the caller", service)
		}
	}
	path := createReq("bivouac-b")
	path.Create.Image = `C:\Windows\System32\config\SAM.vhdx`
	if resp := call(t, s, alice, path); resp.Code != CodeRefused {
		t.Fatal("caller chose an image path", resp)
	}
}

func TestAccountsCannotSeeOrStopEachOthersGuests(t *testing.T) {
	s, n := serverFixture(t)
	if resp := call(t, s, alice, createReq("bivouac-a")); resp.Code != "" {
		t.Fatal(resp)
	}
	for _, op := range []string{"status", "destroy"} {
		if resp := call(t, s, bob, Request{Op: op, Name: "bivouac-a"}); resp.Code != CodeNotFound {
			t.Fatal("other account reached the guest", op, resp)
		}
	}
	if resp := call(t, s, bob, Request{Op: "list"}); len(resp.Guests) != 0 {
		t.Fatal("other account listed the guest")
	}
	if resp := call(t, s, alice, Request{Op: "list"}); len(resp.Guests) != 1 {
		t.Fatal("owner cannot list the guest")
	}
	if resp := call(t, s, alice, Request{Op: "status", Name: "bivouac-a"}); resp.Guest == nil || resp.Guest.State != StateRunning {
		t.Fatal("owner status", resp)
	}
	if resp := call(t, s, alice, Request{Op: "destroy", Name: "bivouac-a"}); resp.Code != "" || resp.Guest.State != StateAbsent || len(n.systems) != 0 {
		t.Fatal("owner destroy", resp)
	}
}

func TestLimitsApplyAcrossAccounts(t *testing.T) {
	s, _ := serverFixture(t)
	big := createReq("bivouac-big")
	big.Create.CPU = 9
	if resp := call(t, s, alice, big); resp.Code != CodeRefused {
		t.Fatal("CPU limit ignored", resp)
	}
	if call(t, s, alice, createReq("bivouac-a")).Code != "" || call(t, s, bob, createReq("bivouac-b")).Code != "" {
		t.Fatal("creates within limits refused")
	}
	if resp := call(t, s, alice, createReq("bivouac-c")); resp.Code != CodeRefused {
		t.Fatal("instance limit ignored", resp)
	}
	if resp := call(t, s, bob, createReq("bivouac-a")); resp.Code != CodeRefused {
		t.Fatal("duplicate name accepted", resp)
	}
	info := call(t, s, bob, Request{Op: "info"}).Info
	if info == nil || info.Running != 2 || info.RunningCPU != 4 || info.RunningMB != 8192 || len(info.Images) != 1 {
		t.Fatal("shared capacity misreported", info)
	}
}

func TestDestroyAllEndsGuestsAndRefusesNewWork(t *testing.T) {
	s, n := serverFixture(t)
	if call(t, s, alice, createReq("bivouac-a")).Code != "" {
		t.Fatal("create failed")
	}
	if err := s.DestroyAll(t.Context()); err != nil || len(n.systems) != 0 || len(entries(t, s.host)) != 0 {
		t.Fatal("guests survived VM host exit", err)
	}
	if resp := call(t, s, alice, createReq("bivouac-b")); resp.Code != CodeRefused {
		t.Fatal("stopping VM host accepted work", resp)
	}
}

func TestMalformedRequestsAreRefused(t *testing.T) {
	s, _ := serverFixture(t)
	for _, req := range []any{
		Request{Op: "format-disk"},
		map[string]any{"op": "info", "extra": true},
		Request{Op: "create"},
		map[string]string{"op": strings.Repeat("x", maxRequest)},
	} {
		if resp := call(t, s, alice, req); resp.Code != CodeRefused {
			t.Fatal("malformed request served", resp)
		}
	}
}

func TestPipeDescriptorGrantsOnlyReadWriteData(t *testing.T) {
	pipe := pipeDescriptor([]string{alice})
	if !strings.Contains(pipe, "(A;;0x120083;;;"+alice+")") || strings.Count(pipe, "GA") != 2 {
		t.Fatal("pipe descriptor grants accounts more than read/write data", pipe)
	}
}

// A real pipe proves caller identification and the client's squatting check.
func TestPipeIdentifiesCallersAndClientsRefuseUnprivilegedServers(t *testing.T) {
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := me.User.Sid.String()
	var suffix [6]byte
	_, _ = rand.Read(suffix[:])
	name := PipeName + "-test-" + hex.EncodeToString(suffix[:])
	// go-winio opens a new instance per accept, which needs the create-instance
	// right production servers hold as SYSTEM or Administrators. This unelevated
	// test server holds it as its own account.
	l, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: pipeDescriptor([]string{sid}) + "(A;;GA;;;" + sid + ")"})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := fixture(t)
	s := NewServer(h, Config{Root: h.dir, Controller: "test", Accounts: []string{sid}, Images: map[string]string{"win": `C:\Images\prepared.vhdx`}, MaxInstances: 1, MaxCPU: 4, MaxMemoryMB: 8192})
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx, l) }()
	defer func() { cancel(); <-served }()

	trusting := &Client{pipe: name, verifyServer: func(windows.Handle) error { return nil }}
	callCtx, done := context.WithTimeout(t.Context(), 10*time.Second)
	defer done()
	if info, err := trusting.Info(callCtx); err != nil || info.Controller != "test" {
		t.Fatal("identified caller refused", info, err)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		if _, err := (&Client{pipe: name, verifyServer: elevatedServer}).Info(callCtx); err == nil {
			t.Fatal("client trusted a pipe served by an unprivileged process")
		}
	}
	// An anonymous-level client cannot be identified, so it is refused.
	conn, err := winio.DialPipe(name, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err = json.NewEncoder(conn).Encode(Request{Op: "info"}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err = json.NewDecoder(conn).Decode(&resp); err != nil || resp.Code != CodeRefused {
		t.Fatal("anonymous caller served", resp, err)
	}
}

func TestLabelsAreBoundedAndReturnedOnlyToTheOwner(t *testing.T) {
	s, _ := serverFixture(t)
	req := createReq("bivouac-a")
	req.Create.Labels = map[string]string{"controller_id": "ctl-1", "instance_id": "0a1b2c3d"}
	if resp := call(t, s, alice, req); resp.Code != "" || resp.Guest.Labels["instance_id"] != "0a1b2c3d" {
		t.Fatal("labels not recorded", resp)
	}
	if resp := call(t, s, alice, Request{Op: "list"}); len(resp.Guests) != 1 || resp.Guests[0].Labels["controller_id"] != "ctl-1" {
		t.Fatal("labels not listed", resp)
	}
	if resp := call(t, s, alice, Request{Op: "status", Name: "bivouac-a"}); resp.Guest.Labels["controller_id"] != "ctl-1" {
		t.Fatal("labels not in status", resp)
	}
	for _, labels := range []map[string]string{{"Bad": "x"}, {"key": "has space"}, {"key": "a;b"}} {
		bad := createReq("bivouac-b")
		bad.Create.Labels = labels
		if resp := call(t, s, alice, bad); resp.Code != CodeRefused {
			t.Fatal("invalid labels accepted", labels)
		}
	}
}

func networkServerFixture(t *testing.T) (*Server, *fakeNative, *fakeNetwork) {
	t.Helper()
	s, n := serverFixture(t)
	return s, n, attachNetwork(t, s.host, n)
}

func createNetworkRequest(t *testing.T, s *Server) *GuestInfo {
	t.Helper()
	req := createReq("bivouac-net")
	req.Create.Network = true
	resp := call(t, s, alice, req)
	if resp.Code != "" || resp.Guest == nil {
		t.Fatal("network create failed", resp)
	}
	return resp.Guest
}

func requireStoppedInStatusAndList(t *testing.T, s *Server, name string) {
	t.Helper()
	resp := call(t, s, alice, Request{Op: "status", Name: name})
	if resp.Code != "" || resp.Guest == nil || resp.Guest.State != StateStopped {
		t.Fatal("quarantined guest not stopped in status", resp)
	}
	resp = call(t, s, alice, Request{Op: "list"})
	if len(resp.Guests) != 1 || resp.Guests[0].Name != name || resp.Guests[0].State != StateStopped {
		t.Fatal("quarantined guest not stopped in list", resp)
	}
}

func requireGuardRefusesCreate(t *testing.T, s *Server) {
	t.Helper()
	resp := call(t, s, alice, createReq("bivouac-next"))
	if resp.Code != CodeRefused || !strings.Contains(resp.Error, "network guard") {
		t.Fatal("network guard did not refuse admission", resp)
	}
}

func requireOwnerDestroyAbsent(t *testing.T, s *Server, name string) {
	t.Helper()
	resp := call(t, s, alice, Request{Op: "destroy", Name: name})
	if resp.Code != "" || resp.Guest == nil || resp.Guest.State != StateAbsent {
		t.Fatal("owner could not acknowledge destruction", resp)
	}
	info := call(t, s, alice, Request{Op: "info"}).Info
	if info == nil || info.Running != 0 || info.RunningCPU != 0 || info.RunningMB != 0 || len(s.guests) != 0 {
		t.Fatal("destroy did not release capacity", info)
	}
}

func requireAdmissionReopens(t *testing.T, s *Server) {
	t.Helper()
	s.guardPass(t.Context())
	if resp := call(t, s, alice, createReq("bivouac-next")); resp.Code != "" {
		t.Fatal("successful full guard pass did not reopen admission", resp)
	}
}

func TestFailedCreateWhoseCleanupFailsKeepsItsReservation(t *testing.T) {
	s, _, f := networkServerFixture(t)
	f.verify.once = errors.New("policy verification failed")
	f.delete.sticky = hostnet.ErrForeign
	req := createReq("bivouac-net")
	req.Create.Network = true
	if resp := call(t, s, alice, req); resp.Code != CodeFailed {
		t.Fatal("failed create reported success", resp)
	}
	if info := s.info(); info.Running != 1 || info.RunningCPU != 2 || info.RunningMB != 4096 {
		t.Fatal("reservation released while the guest's cleanup is unfinished", info)
	}
	if resp := call(t, s, alice, Request{Op: "status", Name: "bivouac-net"}); resp.Code != CodeNotFound {
		t.Fatal("retained create became visible as a guest", resp)
	}
}

func TestPipeNetworkLeaseInCreateStatusAndList(t *testing.T) {
	s, _, f := networkServerFixture(t)
	f.portBeforeStart = true
	g := createNetworkRequest(t, s)
	p := f.networks[g.Name]
	want := &NetworkLease{Address: p.Address, Gateway: p.Gateway, Prefix: 28, MAC: p.MAC}
	if _, timed := g.TimingsMS["protect"]; !reflect.DeepEqual(g.Network, want) || !g.ProtectedBeforeStart || !timed {
		t.Fatal("create omitted or changed network lease or protect path", g.Network)
	}
	status := call(t, s, alice, Request{Op: "status", Name: g.Name})
	list := call(t, s, alice, Request{Op: "list"})
	if status.Guest == nil || !reflect.DeepEqual(status.Guest.Network, want) || len(list.Guests) != 1 || !reflect.DeepEqual(list.Guests[0].Network, want) {
		t.Fatal("status or list omitted network lease", status, list)
	}
	resp := call(t, s, alice, createReq("bivouac-offline"))
	if resp.Code != "" || resp.Guest == nil || resp.Guest.Network != nil {
		t.Fatal("non-network create returned a lease", resp)
	}
	status = call(t, s, alice, Request{Op: "status", Name: "bivouac-offline"})
	list = call(t, s, alice, Request{Op: "list"})
	if status.Guest == nil || status.Guest.Network != nil || len(list.Guests) != 2 || list.Guests[1].Network != nil {
		t.Fatal("non-network status or list returned a lease", status, list)
	}
}

func TestGuardQuarantinesByBlockUntilOwnerDestroyAndFullPass(t *testing.T) {
	s, n, f := networkServerFixture(t)
	g := createNetworkRequest(t, s)
	f.verify.once = errors.New("policy changed")
	s.guardPass(t.Context())
	if f.verify.calls != 2 || f.block.calls != 1 || n.terminateCalls != 0 || !s.guests[g.Name].quarantined || s.guests[g.Name].guardDestroyed {
		t.Fatal("failed network was not blocked and quarantined")
	}
	requireStoppedInStatusAndList(t, s, g.Name)
	requireGuardRefusesCreate(t, s)
	s.guardPass(t.Context()) // Verify would pass now, but quarantine is permanent.
	if f.verify.calls != 2 {
		t.Fatal("guard reverified a quarantined guest")
	}
	requireGuardRefusesCreate(t, s)
	requireOwnerDestroyAbsent(t, s, g.Name)
	requireNetworkGone(t, s.host, n, f)
	requireGuardRefusesCreate(t, s)
	requireAdmissionReopens(t, s)
}

func TestGuardQuarantinesByDestroyAndOwnerReleasesReservation(t *testing.T) {
	s, n, f := networkServerFixture(t)
	g := createNetworkRequest(t, s)
	f.verify.sticky = errors.New("policy changed")
	f.block.once = errors.New("block unavailable")
	s.guardPass(t.Context())
	if f.block.calls != 1 || !s.guests[g.Name].guardDestroyed || !s.guests[g.Name].quarantined {
		t.Fatal("unblockable guest was not recorded as destroyed")
	}
	requireNetworkGone(t, s.host, n, f)
	requireStoppedInStatusAndList(t, s, g.Name)
	info := call(t, s, alice, Request{Op: "info"}).Info
	if info == nil || info.Running != 1 || info.RunningCPU != 2 || info.RunningMB != 4096 {
		t.Fatal("reservation released before owner acknowledgement", info)
	}
	requireGuardRefusesCreate(t, s)
	s.guardPass(t.Context())
	requireGuardRefusesCreate(t, s)
	opens, properties, deletes := n.openCalls, n.propertyCalls, f.delete.calls
	requireOwnerDestroyAbsent(t, s, g.Name)
	if n.openCalls != opens || n.propertyCalls != properties || f.delete.calls != deletes {
		t.Fatal("owner destroy reentered host after confirmed guard cleanup")
	}
	requireGuardRefusesCreate(t, s)
	requireAdmissionReopens(t, s)
}

func TestGuardFailedDestroyOwnerRetriesByName(t *testing.T) {
	s, n, f := networkServerFixture(t)
	g := createNetworkRequest(t, s)
	f.verify.once = errors.New("policy changed")
	f.block.once = errors.New("block unavailable")
	n.terminateErr = errors.New("terminate unavailable")
	s.guardTimeout = 300 * time.Millisecond // the guest outlives the guard's attempt
	s.guardPass(t.Context())
	if s.guests[g.Name].guardDestroyed || n.terminateCalls != 1 || len(n.systems) != 1 || f.delete.calls != 0 {
		t.Fatal("failed guard destroy was treated as confirmed absence")
	}
	requireStoppedInStatusAndList(t, s, g.Name)
	opens := n.openCalls
	n.terminateErr = nil
	requireOwnerDestroyAbsent(t, s, g.Name)
	if n.openCalls <= opens || n.terminateCalls != 2 {
		t.Fatal("owner did not retry cleanup by name")
	}
	requireNetworkGone(t, s.host, n, f)
}

func TestDestroyAllDropsGuardDestroyedEntries(t *testing.T) {
	s, n, f := networkServerFixture(t)
	createNetworkRequest(t, s)
	f.verify.once = errors.New("policy changed")
	f.block.once = errors.New("block unavailable")
	s.guardPass(t.Context())
	opens := n.openCalls
	if err := s.DestroyAll(t.Context()); err != nil || len(s.guests) != 0 || n.openCalls != opens {
		t.Fatal("DestroyAll reentered host for a guard-destroyed guest", err)
	}
	if info := s.info(); info.Running != 0 || info.RunningCPU != 0 || info.RunningMB != 0 {
		t.Fatal("DestroyAll retained reservation", info)
	}
	requireNetworkGone(t, s.host, n, f)
}

func TestGuardBusyGuestKeepsAdmissionClosedUntilFullPass(t *testing.T) {
	s, _, f := networkServerFixture(t)
	g := createNetworkRequest(t, s)
	s.mu.Lock()
	s.admission = errors.New("earlier guard failure")
	s.guests[g.Name].busy = true
	s.mu.Unlock()
	s.guardPass(t.Context())
	if f.verify.calls != 1 {
		t.Fatal("guard checked a busy guest")
	}
	requireGuardRefusesCreate(t, s)
	s.mu.Lock()
	s.guests[g.Name].busy = false
	s.mu.Unlock()
	requireAdmissionReopens(t, s)
	if f.verify.calls != 2 {
		t.Fatal("full pass did not check the networked guest")
	}
}

func TestGuardCanceledPassPreservesAdmissionAndQuarantine(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(fmt.Sprintf("closed=%t", closed), func(t *testing.T) {
			s, n, f := networkServerFixture(t)
			g := createNetworkRequest(t, s)
			var admission error
			if closed {
				admission = errors.New("earlier guard failure")
			}
			s.admission = admission
			f.verify.sticky = errors.New("policy changed")
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			s.guardPass(ctx)
			o := s.guests[g.Name]
			if !errors.Is(s.admission, admission) || o.quarantined || o.guardDestroyed || o.busy || o.guardChecking || f.block.calls != 0 || n.terminateCalls != 0 {
				t.Fatal("canceled guard pass changed admission or quarantine")
			}
		})
	}
}

func TestGuardNeverVerifiesOrQuarantinesNonNetworkGuests(t *testing.T) {
	s, n, f := networkServerFixture(t)
	if resp := call(t, s, alice, createReq("bivouac-offline")); resp.Code != "" {
		t.Fatal(resp)
	}
	f.verify.sticky = errors.New("policy changed")
	s.guardPass(t.Context())
	if f.verify.calls != 0 || f.block.calls != 0 || n.terminateCalls != 0 || s.guests["bivouac-offline"].quarantined || s.admission != nil {
		t.Fatal("guard operated on a non-network guest")
	}
}

func TestStatusDuringGuardCheckReturnsRecordedStateWithoutNativeCall(t *testing.T) {
	for _, quarantined := range []bool{false, true} {
		t.Run(fmt.Sprintf("quarantined=%t", quarantined), func(t *testing.T) {
			s, n, f := networkServerFixture(t)
			g := createNetworkRequest(t, s)
			entered, release := make(chan struct{}), make(chan struct{})
			f.verifyEntered, f.verifyRelease = entered, release
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			done := make(chan struct{})
			go func() { defer close(done); s.guardPass(ctx) }()
			t.Cleanup(func() { cancel(); <-done })
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("guard never entered Verify")
			}
			s.mu.Lock()
			s.guests[g.Name].quarantined = quarantined
			s.mu.Unlock()
			n.mu.Lock()
			opens, properties := n.openCalls, n.propertyCalls
			n.mu.Unlock()
			resp := call(t, s, alice, Request{Op: "status", Name: g.Name})
			want := StateRunning
			if quarantined {
				want = StateStopped
			}
			if resp.Code != "" || resp.Guest == nil || resp.Guest.State != want || !reflect.DeepEqual(resp.Guest.Network, g.Network) {
				t.Fatal("guard claim prevented recorded status", resp)
			}
			if resp := call(t, s, bob, Request{Op: "status", Name: g.Name}); resp.Code != CodeNotFound {
				t.Fatal("guard claim bypassed account ownership", resp)
			}
			n.mu.Lock()
			unchanged := n.openCalls == opens && n.propertyCalls == properties
			n.mu.Unlock()
			if !unchanged {
				t.Fatal("status called native backend during guard check")
			}
			if resp := call(t, s, alice, Request{Op: "destroy", Name: g.Name}); resp.Code != CodeRefused {
				t.Fatal("destroy interrupted guard claim", resp)
			}
			close(release)
			<-done
		})
	}
}

func TestStatusDuringRequestClaimRemainsBusy(t *testing.T) {
	s, n := serverFixture(t)
	if resp := call(t, s, alice, createReq("bivouac-a")); resp.Code != "" {
		t.Fatal(resp)
	}
	s.mu.Lock()
	s.guests["bivouac-a"].busy = true
	s.mu.Unlock()
	properties := n.propertyCalls
	if resp := call(t, s, alice, Request{Op: "status", Name: "bivouac-a"}); resp.Code != CodeRefused || !strings.Contains(resp.Error, "busy") || n.propertyCalls != properties {
		t.Fatal("status bypassed a request claim", resp)
	}
}

func TestGuardLoopCancellationLeavesAdmissionAndGuestUnchanged(t *testing.T) {
	s, n, f := networkServerFixture(t)
	g := createNetworkRequest(t, s)
	entered, release := make(chan struct{}), make(chan struct{})
	f.verifyEntered, f.verifyRelease = entered, release
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	done := make(chan struct{})
	go func() { defer close(done); s.Guard(ctx, time.Hour) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("Guard did not begin a pass")
	}
	cancel()
	<-done
	if o := s.guests[g.Name]; o.busy || o.guardChecking || o.quarantined || o.guardDestroyed || s.admission != nil || f.block.calls != 0 || n.terminateCalls != 0 {
		t.Fatal("canceling Guard changed admission or guest")
	}
}
