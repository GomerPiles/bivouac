//go:build windows

package vmhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

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
