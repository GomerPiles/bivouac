//go:build windows

package hcsvm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/vmhost"
)

const controller = "ctl-test"

type fakeHost struct {
	mu         sync.Mutex
	guests     map[string]vmhost.GuestInfo
	creates    []vmhost.CreateRequest
	destroyed  []string
	network    bool
	destroyErr error
}

func (h *fakeHost) Info(context.Context) (vmhost.Info, error) { return vmhost.Info{}, nil }
func (h *fakeHost) Create(_ context.Context, r vmhost.CreateRequest) (vmhost.GuestInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.creates = append(h.creates, r)
	g := vmhost.GuestInfo{Name: r.Name, RuntimeID: "11111111-2222-3333-4444-555555555555", State: vmhost.StateRunning, Labels: r.Labels}
	if h.network {
		g.Network = &vmhost.NetworkLease{Address: "10.250.0.2", Gateway: "10.250.0.1", Prefix: 28, MAC: "02-42-0A-1B-2C-3D"}
	}
	h.guests[r.Name] = g
	return g, nil
}
func (h *fakeHost) Status(_ context.Context, name string) (vmhost.GuestInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	g, ok := h.guests[name]
	if !ok {
		return g, &vmhost.Error{Code: vmhost.CodeNotFound, Message: "no such guest"}
	}
	return g, nil
}
func (h *fakeHost) Destroy(_ context.Context, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.destroyErr != nil {
		return h.destroyErr
	}
	if _, ok := h.guests[name]; !ok {
		return &vmhost.Error{Code: vmhost.CodeNotFound, Message: "no such guest"}
	}
	delete(h.guests, name)
	h.destroyed = append(h.destroyed, name)
	return nil
}
func (h *fakeHost) List(context.Context) ([]vmhost.GuestInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []vmhost.GuestInfo
	for _, g := range h.guests {
		out = append(out, g)
	}
	return out, nil
}

type call struct {
	command string
	stdin   []byte
}

type fakeTransport struct {
	mu       sync.Mutex
	opens    int
	calls    []call
	sent     map[string][]byte
	replies  map[string]string
	fail     error // next Run fails with this once
	duplex   func(context.Context) (net.Conn, error)
	runHook  func(string, []byte) error
	openHook func(context.Context) error
}

func (f *fakeTransport) Open(ctx context.Context, _ string) (Session, error) {
	f.mu.Lock()
	f.opens++
	f.mu.Unlock()
	if f.openHook != nil {
		if err := f.openHook(ctx); err != nil {
			return nil, err
		}
	}
	return &fakeSession{f: f}, nil
}

type fakeSession struct{ f *fakeTransport }

func (s *fakeSession) Run(ctx context.Context, argv []string, input io.Reader, _ int) ([]byte, error) {
	var stdin []byte
	if input != nil {
		stdin, _ = io.ReadAll(input)
	}
	defer clear(stdin)
	command := strings.Join(argv, " ")
	if len(argv) == 6 && argv[1] == "guest-agent" && argv[2] == "receive" {
		s.f.sent[argv[3]] = append([]byte(nil), stdin...)

		return nil, nil
	}
	if len(argv) == 2 && argv[1] == "version" {
		contextTiming(ctx).begin(stepAgentProof)
		return []byte("ok"), nil
	}
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	var recorded []byte
	if !strings.HasSuffix(command, "cache-setup") {
		recorded = append([]byte(nil), stdin...)
	}
	s.f.calls = append(s.f.calls, call{command, recorded})
	if s.f.runHook != nil {
		if err := s.f.runHook(command, stdin); err != nil {
			return nil, err
		}
	}
	if err := s.f.fail; err != nil {
		s.f.fail = nil
		return nil, err
	}
	for suffix, reply := range s.f.replies {
		if strings.HasSuffix(command, suffix) {
			return []byte(reply), nil
		}
	}
	return []byte("ok"), nil
}
func (s *fakeSession) Close() error { return nil }
func (s *fakeSession) Duplex(ctx context.Context, _ []string) (net.Conn, error) {
	if s.f.duplex == nil {
		return nil, errors.New("cache agent unavailable")
	}
	return s.f.duplex(ctx)
}

func fixture(t *testing.T, network bool) (*Provider, *fakeHost, *fakeTransport) {
	t.Helper()
	helper := filepath.Join(t.TempDir(), "bivouac.exe")
	if err := os.WriteFile(helper, []byte("helper"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &fakeHost{guests: map[string]vmhost.GuestInfo{}, network: network}
	f := &fakeTransport{sent: map[string][]byte{}, replies: map[string]string{
		"guest windows preflight": `{"ready":true,"session":1}`,
		"guest windows prepare":   `{"ready":true,"session":1,"desktop":"Default"}`,
		"guest windows gpu":       `{"hardware_d3d12":true}`,
		"guest windows status":    `{"State":"listening"}`,
		"guest windows clock":     "2026-10-21T08:38:01.0000000Z\r\n",
	}}
	p, err := New(Options{Name: "windows", ControllerID: controller, Image: "windows", GuestName: "bivouac-image", GuestUser: "ciuser", CPU: 4, MemoryMB: 8192, GPU: true, RunnerDir: `C:\actions-runner`, Helper: helper}, h, f)
	if err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return hostNow }
	return p, h, f
}

var hostNow = time.Date(2026, 10, 21, 8, 38, 0, 0, time.UTC)

func TestWaitReadySetsTheGuestClockFromTheHost(t *testing.T) {
	p, _, f := fixture(t, true)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	if err := p.WaitReady(t.Context(), "bivouac-windows-0a1b2c3d"); err != nil {
		t.Fatal(err)
	}
	last := f.calls[len(f.calls)-1]
	if last.command != guestHelper+" guest windows clock" || string(last.stdin) != "2026-10-21T08:38:00.0000000Z\n" {
		t.Fatal("clock not set from the host over stdin", last.command, string(last.stdin))
	}
	f.replies["guest windows clock"] = "2026-10-21T09:38:00.0000000Z"
	if err := p.WaitReady(t.Context(), "bivouac-windows-0a1b2c3d"); err == nil || !strings.Contains(err.Error(), "1h0m0s off") {
		t.Fatal("a guest clock left an hour off was accepted", err)
	}
}

func spec() provider.Spec {
	const id = "0a1b2c3d"
	return provider.Spec{Name: "bivouac-windows-" + id, Meta: provider.Metadata{ControllerID: controller, InstanceID: id, CreatedAt: "2026-10-19T14:00:00Z"}}
}

func TestCreateRequestsOnlyThisControllersGuest(t *testing.T) {
	p, h, _ := fixture(t, true)
	for _, bad := range []provider.Spec{
		{Name: "bivouac-windows-0a1b2c3d", Meta: provider.Metadata{ControllerID: "other", InstanceID: "0a1b2c3d"}},
		{Name: "bivouac-linux-0a1b2c3d", Meta: provider.Metadata{ControllerID: controller, InstanceID: "0a1b2c3d"}},
		{Name: "bivouac-windows-0a1b2c3d", Meta: provider.Metadata{ControllerID: controller, InstanceID: "ffffffff"}},
	} {
		if err := p.Create(t.Context(), bad); !errors.Is(err, provider.ErrNotOwned) {
			t.Fatal("foreign spec accepted", bad.Name, err)
		}
	}
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	r := h.creates[0]
	if r.Image != "windows" || r.CPU != 4 || r.MemoryMB != 8192 || !r.GPU || !r.Network || len(r.Services) != 1 || r.Services[0] != guestagent.ServiceID || r.Labels["controller_id"] != controller || r.Labels["instance_id"] != "0a1b2c3d" {
		t.Fatal("create request", r)
	}
	if st, err := p.Status(t.Context(), "bivouac-windows-0a1b2c3d"); err != nil || !st.Exists || !st.Running || !st.Owned || st.Meta.InstanceID != "0a1b2c3d" {
		t.Fatal("status", st, err)
	}
}

func TestGuestsWithoutThisControllersLabelsAreNotOwned(t *testing.T) {
	p, h, _ := fixture(t, true)
	h.guests["bivouac-windows-0a1b2c3d"] = vmhost.GuestInfo{Name: "bivouac-windows-0a1b2c3d", State: vmhost.StateRunning, Labels: map[string]string{"controller_id": "other", "instance_id": "0a1b2c3d"}}
	if st, err := p.Status(t.Context(), "bivouac-windows-0a1b2c3d"); err != nil || !st.Exists || st.Owned {
		t.Fatal("foreign guest reported owned", st, err)
	}
	if err := p.Delete(t.Context(), "bivouac-windows-0a1b2c3d"); !errors.Is(err, provider.ErrNotOwned) || len(h.destroyed) != 0 {
		t.Fatal("foreign guest destroyed", err)
	}
	owned, foreign, err := p.List(t.Context())
	if err != nil || len(owned) != 0 || len(foreign) != 1 || !foreign[0].Prefixed {
		t.Fatal("foreign guest listed as owned", owned, foreign, err)
	}
}

func TestWaitReadyProvesConsoleThenInstallsAdapter(t *testing.T) {
	p, _, f := fixture(t, true)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	if err := p.WaitReady(t.Context(), "bivouac-windows-0a1b2c3d"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(f.calls[0].command, "guest windows preflight") || !strings.HasSuffix(f.calls[1].command, "guest windows prepare") {
		t.Fatal("readiness order", f.calls)
	}
	for _, name := range []string{"bivouac-config.json", "bivouac-helper.exe"} {
		if _, ok := f.sent[name]; !ok {
			t.Fatal("missing guest file", name)
		}
	}
	if !bytes.Contains(f.sent["bivouac-config.json"], []byte(`"mac":"02-42-0A-1B-2C-3D"`)) || !bytes.Contains(f.sent["bivouac-config.json"], []byte(`"native_name":"bivouac-image"`)) {
		t.Fatal("guest config", string(f.sent["bivouac-config.json"]))
	}
}

func TestWaitReadyRefusesAGuestWithoutNetwork(t *testing.T) {
	p, _, f := fixture(t, false)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	if err := p.WaitReady(t.Context(), "bivouac-windows-0a1b2c3d"); err == nil || len(f.calls) != 0 {
		t.Fatal("prepared a guest that cannot reach GitHub", err)
	}
}

func TestJITTravelsOnlyOnStdin(t *testing.T) {
	p, _, f := fixture(t, true)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	jit := []byte("synthetic-jit-secret")
	if err := p.StartRunner(t.Context(), "bivouac-windows-0a1b2c3d", jit); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.Contains(c.command, "synthetic-jit-secret") {
			t.Fatal("JIT reached a command line")
		}
	}
	if !bytes.Equal(f.calls[0].stdin, jit) || !strings.HasSuffix(f.calls[0].command, "seed-jit") || !strings.HasSuffix(f.calls[1].command, "guest windows start") {
		t.Fatal("JIT delivery", f.calls)
	}
}

func TestTransportFailureReconnectsOnTheNextProbe(t *testing.T) {
	p, _, f := fixture(t, true)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	f.fail = provider.GuestAgentUnavailable
	if _, err := p.RunnerStatus(t.Context(), "bivouac-windows-0a1b2c3d"); !errors.Is(err, provider.GuestAgentUnavailable) {
		t.Fatal("transport failure not reported as retryable", err)
	}
	status, err := p.RunnerStatus(t.Context(), "bivouac-windows-0a1b2c3d")
	if err != nil || status.State != provider.RunnerListening || f.opens != 2 {
		t.Fatal("probe did not reconnect", status, err, f.opens)
	}
}

func TestDeleteDestroysAndForgetsGuest(t *testing.T) {
	p, h, _ := fixture(t, true)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RunnerStatus(t.Context(), "bivouac-windows-0a1b2c3d"); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(t.Context(), "bivouac-windows-0a1b2c3d"); err != nil || len(h.destroyed) != 1 {
		t.Fatal("delete", err)
	}
	if err := p.Delete(t.Context(), "bivouac-windows-0a1b2c3d"); err != nil {
		t.Fatal("absent guest delete failed", err)
	}
	if st, err := p.Status(t.Context(), "bivouac-windows-0a1b2c3d"); err != nil || st.Exists {
		t.Fatal("absent guest status", st, err)
	}
}
