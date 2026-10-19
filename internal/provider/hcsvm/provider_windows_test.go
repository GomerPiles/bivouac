//go:build windows

package hcsvm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/vmhost"
)

const controller = "ctl-test"

type fakeHost struct {
	mu        sync.Mutex
	guests    map[string]vmhost.GuestInfo
	creates   []vmhost.CreateRequest
	destroyed []string
	network   bool
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
	mu      sync.Mutex
	opens   int
	calls   []call
	sent    map[string][]byte
	replies map[string]string
	fail    error // next Run fails with this once
}

func (f *fakeTransport) Open(_ context.Context, _, _ string, pin Pin) (Session, error) {
	f.mu.Lock()
	f.opens++
	f.mu.Unlock()
	fingerprint := strings.Repeat("ab", 32)
	if err := pin.Check(fingerprint); err != nil {
		return nil, err
	}
	return &fakeSession{f: f}, nil
}

type fakeSession struct{ f *fakeTransport }

func (s *fakeSession) Run(_ context.Context, command string, stdin []byte, _ int) ([]byte, error) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	s.f.calls = append(s.f.calls, call{command, append([]byte(nil), stdin...)})
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
func (s *fakeSession) Send(_ context.Context, name string, data io.Reader, size int64) error {
	b, err := io.ReadAll(data)
	if err != nil || int64(len(b)) != size {
		return errors.New("short send")
	}
	s.f.mu.Lock()
	s.f.sent[name] = b
	s.f.mu.Unlock()
	return nil
}
func (s *fakeSession) Close() error { return nil }

func fixture(t *testing.T, network bool) (*Provider, *fakeHost, *fakeTransport) {
	t.Helper()
	helper := filepath.Join(t.TempDir(), "bivouac.exe")
	if err := os.WriteFile(helper, []byte("helper"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &fakeHost{guests: map[string]vmhost.GuestInfo{}, network: network}
	f := &fakeTransport{sent: map[string][]byte{}, replies: map[string]string{
		"bivouac-preflight.ps1": `{"ready":true,"session":1}`,
		"-Mode prepare":         `{"ready":true,"session":1,"desktop":"Default"}`,
		"guest windows status":  `{"State":"listening"}`,
	}}
	p, err := New(Options{Name: "windows", ControllerID: controller, Image: "windows", GuestName: "bivouac-image", GuestUser: "ciuser", CPU: 4, MemoryMB: 8192, GPU: true, RunnerDir: `C:\actions-runner`, Helper: helper, StateDir: t.TempDir()}, h, f)
	if err != nil {
		t.Fatal(err)
	}
	return p, h, f
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
	if r.Image != "windows" || r.CPU != 4 || r.MemoryMB != 8192 || !r.GPU || len(r.Services) != 2 || r.Labels["controller_id"] != controller || r.Labels["instance_id"] != "0a1b2c3d" {
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
	if !strings.HasSuffix(f.calls[0].command, "bivouac-preflight.ps1") || !strings.HasSuffix(f.calls[1].command, "-Mode prepare") {
		t.Fatal("readiness order", f.calls)
	}
	for _, name := range []string{"bivouac-preflight.ps1", "bivouac-config.json", "bivouac-control.ps1", "bivouac-helper.exe"} {
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
	if !bytes.Equal(f.calls[0].stdin, jit) || !strings.HasSuffix(f.calls[0].command, "seed-jit") || !strings.HasSuffix(f.calls[1].command, "-Mode start") {
		t.Fatal("JIT delivery", f.calls)
	}
}

func TestTransportFailureReconnectsOnTheNextProbe(t *testing.T) {
	p, _, f := fixture(t, true)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	f.fail = provider.SSHClosed
	if _, err := p.RunnerStatus(t.Context(), "bivouac-windows-0a1b2c3d"); !errors.Is(err, provider.SSHClosed) {
		t.Fatal("transport failure not reported as retryable", err)
	}
	status, err := p.RunnerStatus(t.Context(), "bivouac-windows-0a1b2c3d")
	if err != nil || status.State != provider.RunnerListening || f.opens != 2 {
		t.Fatal("probe did not reconnect", status, err, f.opens)
	}
}

func TestHostKeyPinRefusesADifferentKey(t *testing.T) {
	pin := filePin{path: filepath.Join(t.TempDir(), "0a1b2c3d.hostkey")}
	if err := pin.Check(strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	if err := pin.Check(strings.Repeat("ab", 32)); err != nil {
		t.Fatal("same key refused", err)
	}
	if err := pin.Check(strings.Repeat("cd", 32)); !errors.Is(err, provider.SSHHostKey) {
		t.Fatal("different key accepted", err)
	}
	if err := pin.Check("not-a-fingerprint"); err == nil {
		t.Fatal("invalid fingerprint accepted")
	}
}

func TestDeleteDestroysAndForgetsThePin(t *testing.T) {
	p, h, _ := fixture(t, true)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RunnerStatus(t.Context(), "bivouac-windows-0a1b2c3d"); err != nil {
		t.Fatal(err)
	}
	pin := filepath.Join(p.opts.StateDir, "0a1b2c3d.hostkey")
	if _, err := os.Stat(pin); err != nil {
		t.Fatal("host key not pinned")
	}
	if err := p.Delete(t.Context(), "bivouac-windows-0a1b2c3d"); err != nil || len(h.destroyed) != 1 {
		t.Fatal("delete", err)
	}
	if _, err := os.Stat(pin); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pin outlived its guest")
	}
	if err := p.Delete(t.Context(), "bivouac-windows-0a1b2c3d"); err != nil {
		t.Fatal("absent guest delete failed", err)
	}
	if st, err := p.Status(t.Context(), "bivouac-windows-0a1b2c3d"); err != nil || st.Exists {
		t.Fatal("absent guest status", st, err)
	}
}
