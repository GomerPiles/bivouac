//go:build windows

package vmhost

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/hcs"
	"golang.org/x/sys/windows"
)

// fakeNative models HCS names, owners and lifetimes without Hyper-V.
type fakeNative struct {
	mu             sync.Mutex
	t              *testing.T
	host           *Host
	systems        map[string]*fakeSystem
	createErr      error
	owner          string // overrides the owner HCS reports, if set
	lingers        int    // absence polls before a terminated guest disappears
	created        []string
	sawIntent      bool
	lastDocument   hcs.ComputeSystem
	beforeMutation func()
	openCalls      int
	propertyCalls  int
	terminateCalls int
	terminateErr   error
	// startErr fails Start; afterFailedStart then changes what the guest's
	// properties report, as a real failed start can.
	startErr         error
	afterFailedStart func(*hcs.Properties)
	propertiesErr    error
	// terminateOnClose ends a guest when its creating handle closes, as
	// TerminateOnLastHandleClosed does.
	terminateOnClose bool
}

type fakeSystem struct {
	n       *fakeNative
	name    string
	props   hcs.Properties
	closed  bool
	creator bool // returned by Create rather than Open
}

func (n *fakeNative) Open(_ context.Context, name string) (system, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.openCalls++
	s, ok := n.systems[name]
	if !ok {
		return nil, hcs.ErrNotFound
	}
	if s.props.State == hcs.StateStopped && n.lingers > 0 {
		n.lingers--
	} else if s.props.State == hcs.StateStopped {
		delete(n.systems, name)
		return nil, hcs.ErrNotFound
	}
	return &fakeSystem{n: n, name: name, props: s.props}, nil
}

func (n *fakeNative) Create(_ context.Context, name string, doc hcs.ComputeSystem) (system, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.mutating()
	n.lastDocument = doc
	var r record
	if err := n.host.read(recordName(name), &r); err != nil || r.Phase != phaseDispatched {
		n.t.Error("create dispatched before its intent was journalled")
	}
	n.sawIntent = true
	if n.createErr != nil {
		return nil, n.createErr
	}
	owner := doc.Owner
	if n.owner != "" {
		owner = n.owner
	}
	s := &fakeSystem{n: n, name: name, props: hcs.Properties{ID: name, Owner: owner, SystemType: hcs.SystemTypeVM, State: "Created"}, creator: true}
	n.systems[name] = s
	n.created = append(n.created, name)
	return s, nil
}

func (n *fakeNative) mutating() {
	if n.beforeMutation != nil {
		n.beforeMutation()
	}
}

func (n *fakeNative) GrantVMAccess(string, string) error {
	n.mutating()
	return nil
}
func (n *fakeNative) CreateGuestStateFiles(guestState, runtimeState string) error {
	n.mutating()
	return errors.Join(os.WriteFile(guestState, nil, 0o600), os.WriteFile(runtimeState, nil, 0o600))
}
func (n *fakeNative) CreateDisk(child, _ string) error {
	n.mutating()
	return os.WriteFile(child, []byte("disk"), 0o600)
}
func (n *fakeNative) CheckImage(string) error { return nil }

func (s *fakeSystem) Properties(context.Context) (hcs.Properties, error) {
	s.n.mu.Lock()
	defer s.n.mu.Unlock()
	s.n.propertyCalls++
	if s.n.propertiesErr != nil {
		return hcs.Properties{}, s.n.propertiesErr
	}
	if live, ok := s.n.systems[s.name]; ok {
		return live.props, nil
	}
	return hcs.Properties{}, errors.New("compute system gone")
}
func (s *fakeSystem) Start(context.Context) error {
	s.n.mu.Lock()
	defer s.n.mu.Unlock()
	live := s.n.systems[s.name]
	if s.n.startErr != nil {
		live.props.State = hcs.StateStopped
		if s.n.afterFailedStart != nil {
			s.n.afterFailedStart(&live.props)
		}
		return s.n.startErr
	}
	live.props.State, live.props.RuntimeID = hcs.StateRunning, fakeRuntimeID
	return nil
}
func (s *fakeSystem) Terminate(context.Context) error {
	s.n.mu.Lock()
	defer s.n.mu.Unlock()
	s.n.terminateCalls++
	if s.n.terminateErr != nil {
		return s.n.terminateErr
	}
	s.n.systems[s.name].props.State = hcs.StateStopped
	return nil
}
func (s *fakeSystem) Modify(context.Context, hcs.ModifyRequest) error { return nil }
func (s *fakeSystem) Close() {
	s.n.mu.Lock()
	defer s.n.mu.Unlock()
	s.closed = true
	if live, ok := s.n.systems[s.name]; ok && s.creator && s.n.terminateOnClose {
		live.props.State = hcs.StateStopped
	}
}

func fixture(t *testing.T) (*Host, *fakeNative) {
	t.Helper()
	n := &fakeNative{t: t, systems: map[string]*fakeSystem{}}
	h, err := newHost(t.TempDir(), n, "bivouac-vmhost:test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	n.host = h
	return h, n
}

func entries(t *testing.T, h *Host) []string {
	t.Helper()
	list, err := fs.ReadDir(h.root.FS(), ".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range list {
		names = append(names, e.Name())
	}
	return names
}

func TestCreateJournalsFirstAndDestroyLeavesNothing(t *testing.T) {
	h, n := fixture(t)
	g, err := h.Create(t.Context(), validSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !n.sawIntent || g.RuntimeID == "" || h.Running(t.Context(), g) != nil {
		t.Fatal("guest not created, journalled and running")
	}
	for _, file := range []string{diskFile, guestStateFile, runtimeStateFile, "owner.json"} {
		if _, err := os.Stat(filepath.Join(h.dir, g.Name, file)); err != nil {
			t.Fatal("guest storage missing", file)
		}
	}
	n.lingers = 3
	if err = h.Destroy(t.Context(), g); err != nil {
		t.Fatal(err)
	}
	if left := entries(t, h); len(left) != 0 {
		t.Fatal("destroy left storage or journal", left)
	}
}

func TestCreateRefusesAnExistingNativeName(t *testing.T) {
	h, n := fixture(t)
	n.systems["bivouac-lab-1"] = &fakeSystem{n: n, name: "bivouac-lab-1", props: hcs.Properties{ID: "bivouac-lab-1", State: hcs.StateRunning}}
	if _, err := h.Create(t.Context(), validSpec()); err == nil {
		t.Fatal("replaced an existing compute system")
	}
	if left := entries(t, h); len(left) != 0 || n.systems["bivouac-lab-1"].props.State != hcs.StateRunning {
		t.Fatal("refusal touched the foreign guest or journalled it", left)
	}
}

func TestDefiniteCreateFailureRemovesOnlyItsStorage(t *testing.T) {
	h, n := fixture(t)
	n.createErr = &hcs.Error{Op: "HcsCreateComputeSystem", Code: 0x80070005}
	if _, err := h.Create(t.Context(), validSpec()); err == nil {
		t.Fatal("failed create reported success")
	}
	if left := entries(t, h); len(left) != 0 {
		t.Fatal("definite failure retained storage", left)
	}
}

func TestUnknownCreateOutcomeIsRetainedAndNeverReplayed(t *testing.T) {
	h, n := fixture(t)
	n.createErr = &hcs.Error{Op: "HcsCreateComputeSystem", Code: uint32(windows.HCS_E_OPERATION_TIMEOUT)}
	if _, err := h.Create(t.Context(), validSpec()); err == nil {
		t.Fatal("unknown create reported success")
	}
	var r record
	if err := h.read(recordName("bivouac-lab-1"), &r); err != nil || r.Phase != phaseDispatched {
		t.Fatal("unknown outcome not retained", r.Phase, err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "bivouac-lab-1", diskFile)); err != nil {
		t.Fatal("storage of a possibly running guest was removed")
	}
	// A later VM host settles it: the name is absent, so storage is removed.
	n.createErr = nil
	if err := h.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	if left := entries(t, h); len(left) != 0 || len(n.created) != 0 {
		t.Fatal("recovery replayed create or retained storage", left, n.created)
	}
}

func TestForeignOwnerIsNeverStoppedOrDeleted(t *testing.T) {
	h, n := fixture(t)
	n.owner = "someone-else"
	if _, err := h.Create(t.Context(), validSpec()); !errors.Is(err, ErrForeign) {
		t.Fatal("foreign owner accepted", err)
	}
	if s := n.systems["bivouac-lab-1"]; s == nil || s.props.State == hcs.StateStopped {
		t.Fatal("foreign guest was stopped")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "bivouac-lab-1", diskFile)); err != nil {
		t.Fatal("storage of an unproven guest was removed")
	}
	if err := h.Recover(t.Context()); !errors.Is(err, ErrForeign) {
		t.Fatal("recovery bypassed ownership", err)
	}
}

func TestRecoverTerminatesOurSurvivorsAndWaitsForAbsence(t *testing.T) {
	h, n := fixture(t)
	g, err := h.Create(t.Context(), validSpec())
	if err != nil {
		t.Fatal(err)
	}
	g.system.Close() // the earlier VM host's handle is gone
	n.lingers = 2
	if err = h.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	if left := entries(t, h); len(left) != 0 || len(n.systems) != 0 {
		t.Fatal("survivor not settled", left)
	}
}

func TestAbsenceIsRequiredBeforeStorageIsRemoved(t *testing.T) {
	h, n := fixture(t)
	g, err := h.Create(t.Context(), validSpec())
	if err != nil {
		t.Fatal(err)
	}
	n.lingers = 1 << 30
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if err = h.Destroy(ctx, g); err == nil {
		t.Fatal("destroy succeeded while the guest was still present")
	}
	if _, err = os.Stat(filepath.Join(h.dir, g.Name, diskFile)); err != nil {
		t.Fatal("storage removed before absence was confirmed")
	}
}

func TestFailedStartIsCleanedUpWhenItsPropertiesNoLongerProveIt(t *testing.T) {
	startErr := &hcs.Error{Op: "HcsStartComputeSystem", Code: 0x8007139f}
	for name, after := range map[string]func(*fakeNative) func(*hcs.Properties){
		"proven":      func(*fakeNative) func(*hcs.Properties) { return nil },
		"owner":       func(*fakeNative) func(*hcs.Properties) { return func(p *hcs.Properties) { p.Owner = "" } },
		"system type": func(*fakeNative) func(*hcs.Properties) { return func(p *hcs.Properties) { p.SystemType = "" } },
		"properties": func(n *fakeNative) func(*hcs.Properties) {
			return func(*hcs.Properties) { n.propertiesErr = errors.New("unavailable") }
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, n := fixture(t)
			n.startErr, n.afterFailedStart, n.terminateOnClose = startErr, after(n), true
			if _, err := h.Create(t.Context(), validSpec()); !errors.Is(err, startErr) || errors.Is(err, errRetained) {
				t.Fatal("failed start not cleaned up", err)
			}
			if left := entries(t, h); len(left) != 0 || len(n.systems) != 0 {
				t.Fatal("failed start retained its guest or storage", left)
			}
		})
	}
}

func TestUnprovenSystemOpenedByNameIsStillRetained(t *testing.T) {
	h, n := fixture(t)
	g, err := h.Create(t.Context(), validSpec())
	if err != nil {
		t.Fatal(err)
	}
	g.system.Close() // an earlier VM host's handle
	n.systems[g.Name].props.Owner = ""
	if err := h.Recover(t.Context()); !errors.Is(err, ErrForeign) || !strings.Contains(err.Error(), "owner differs") {
		t.Fatal("recovery touched an unproven guest, or did not say why", err)
	}
	if n.terminateCalls != 0 || n.systems[g.Name] == nil {
		t.Fatal("unproven guest was stopped")
	}
}

func TestRecoverIgnoresUnrelatedFiles(t *testing.T) {
	h, _ := fixture(t)
	for _, name := range []string{"daemon.lock", "notes.json", "bivouac-x.json.new"} {
		if err := os.WriteFile(filepath.Join(h.dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(entries(t, h)) != 3 {
		t.Fatal("recovery touched unrelated files")
	}
}
