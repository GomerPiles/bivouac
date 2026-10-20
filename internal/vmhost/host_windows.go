//go:build windows

package vmhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/hcs"
	"github.com/GomerPiles/bivouac/internal/hostnet"
	"github.com/GomerPiles/bivouac/internal/winhost"
	"github.com/Microsoft/go-winio/vhd"
)

// ErrForeign reports a native guest or journal entry that cannot be proven to
// be this host's. Nothing is stopped or deleted; the record is retained.
var ErrForeign = errors.New("guest is not provably owned by this VM host; retained")

type native interface {
	Open(ctx context.Context, name string) (system, error)
	Create(ctx context.Context, name string, doc hcs.ComputeSystem) (system, error)
	GrantVMAccess(name, path string) error
	CreateGuestStateFiles(guestState, runtimeState string) error
	CreateDisk(child, parent string) error
	CheckImage(path string) error
}

type system interface {
	Properties(context.Context) (hcs.Properties, error)
	Start(context.Context) error
	Terminate(context.Context) error
	Modify(context.Context, hcs.ModifyRequest) error
	Close()
}

type hcsNative struct{ api *hcs.API }

func (n hcsNative) Open(ctx context.Context, name string) (system, error) {
	s, err := n.api.Open(ctx, name)
	if err != nil {
		return nil, err
	}
	return s, nil
}
func (n hcsNative) Create(ctx context.Context, name string, doc hcs.ComputeSystem) (system, error) {
	s, err := n.api.Create(ctx, name, doc)
	if err != nil {
		return nil, err
	}
	return s, nil
}
func (n hcsNative) GrantVMAccess(name, path string) error { return n.api.GrantVMAccess(name, path) }
func (n hcsNative) CreateGuestStateFiles(guestState, runtimeState string) error {
	return n.api.CreateGuestStateFiles(guestState, runtimeState)
}
func (hcsNative) CreateDisk(child, parent string) error { return vhd.CreateDiffVhd(child, parent, 0) }
func (hcsNative) CheckImage(path string) error          { return winhost.CheckProtected(path) }

// network is hostnet's Manager, or a fake.
type network interface {
	Plan(ctx context.Context, guest string, retained []hostnet.Plan) (hostnet.Plan, error)
	Create(ctx context.Context, p hostnet.Plan, guest string) error
	Port(ctx context.Context, p hostnet.Plan) (exists, connected bool, err error)
	Protect(ctx context.Context, p hostnet.Plan, guest, runtimeID string) (hostnet.Plan, error)
	Verify(ctx context.Context, p hostnet.Plan, guest string) error
	Block(ctx context.Context, p hostnet.Plan) error
	Delete(ctx context.Context, p hostnet.Plan, guest string) error
}

// Host owns one administrator-protected journal directory and the handles of
// every guest it creates. One Host at a time holds the directory's lock.
type Host struct {
	native native
	net    network // nil when this host cannot attach networks; see netErr
	netErr error
	dir    string
	root   *os.Root
	owner  string
	lock   *control.Lock
}

var controllerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// Open requires an existing administrator-protected directory, takes its
// lock and resolves HCS. It changes nothing; call Recover to settle retained
// guests from an earlier VM host.
func Open(dir, controller string) (*Host, error) {
	if !controllerPattern.MatchString(controller) {
		return nil, errors.New("invalid controller identity")
	}
	if err := winhost.CheckProtected(dir); err != nil {
		return nil, fmt.Errorf("VM host directory is not administrator-protected: %w", err)
	}
	api, err := hcs.Load()
	if err != nil {
		return nil, err
	}
	lock, err := (control.Files{Dir: dir}).Acquire()
	if err != nil {
		return nil, errors.New("VM host directory is locked by another VM host")
	}
	h, err := newHost(dir, hcsNative{api}, "bivouac-vmhost:"+controller)
	if err != nil {
		_ = lock.Release()
		return nil, err
	}
	h.lock = lock
	if manager, err := hostnet.Open(); err != nil {
		h.netErr = fmt.Errorf("guest networking unavailable: %w", err)
	} else {
		h.net = manager
	}
	return h, nil
}

func newHost(dir string, n native, owner string) (*Host, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Host{native: n, dir: dir, root: root, owner: owner}, nil
}

func (h *Host) Close() error {
	err := h.root.Close()
	if h.lock != nil {
		err = errors.Join(err, h.lock.Release())
	}
	return err
}

type phase string

const (
	phaseIntent     phase = "intent"     // storage may be partial; nothing dispatched
	phaseDispatched phase = "dispatched" // create sent; its outcome may be unknown
	phaseCreated    phase = "created"    // this host's exact instance was observed
	phaseFailed     phase = "failed"     // create definitively failed; nothing native
	phaseDeleting   phase = "deleting"   // native absence confirmed; removing storage
)

type record struct {
	Owner     string        `json:"owner"`
	Spec      Spec          `json:"spec"`
	Phase     phase         `json:"phase"`
	RuntimeID string        `json:"runtime_id,omitempty"`
	Network   *hostnet.Plan `json:"network,omitempty"`
}

type marker struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

func recordName(name string) string { return name + ".json" }
func markerName(name string) string { return filepath.Join(name, "owner.json") }

func (h *Host) read(name string, out any) error {
	f, err := h.root.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 || json.Unmarshal(b, out) != nil {
		return errors.New("invalid bounded VM host journal entry")
	}
	return nil
}

// write creates name exclusively, or replaces it through a synced temporary.
func (h *Host) write(name string, value any, exclusive bool) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	target, flags := name, os.O_WRONLY|os.O_CREATE|os.O_EXCL
	if !exclusive {
		target, flags = name+".new", os.O_WRONLY|os.O_CREATE|os.O_TRUNC
	}
	f, err := h.root.OpenFile(target, flags, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err == nil && !exclusive {
		err = h.root.Rename(target, name)
	}
	if err != nil && !exclusive {
		_ = h.root.Remove(target)
	}
	return err
}

// Timings are host-monotonic spans of one guest's creation. Network covers
// the switch and endpoint; Protect covers the port's policy.
type Timings struct {
	Disk, StateFiles, Grants, Network, Create, Protect, Start, GPU time.Duration
	// ProtectedBeforeStart records whether the port existed, and its policy
	// was installed, before the guest ran its first instruction.
	ProtectedBeforeStart bool
}

// Guest is a running guest whose handle this Host holds.
type Guest struct {
	Name      string
	RuntimeID string
	Timings   Timings
	// Network is the guest's committed isolated endpoint, or nil.
	Network *hostnet.Plan
	system  system
}

func (h *Host) prove(name string, r record, p hcs.Properties) error {
	if p.ID != name || p.Owner != h.owner || p.SystemType != hcs.SystemTypeVM || (r.RuntimeID != "" && !strings.EqualFold(r.RuntimeID, p.RuntimeID)) {
		return ErrForeign
	}
	return nil
}

// Create journals the spec, prepares a fresh differencing disk and state
// files, creates and starts the guest and optionally assigns the GPU. A
// failure after dispatch tears the guest down again; an unknown create outcome
// retains its record for Recover.
func (h *Host) Create(ctx context.Context, spec Spec) (_ *Guest, err error) {
	if err = spec.Validate(); err != nil {
		return nil, err
	}
	if err = h.native.CheckImage(spec.Image); err != nil {
		return nil, fmt.Errorf("guest image is not administrator-protected: %w", err)
	}
	if existing, openErr := h.native.Open(ctx, spec.Name); openErr == nil {
		existing.Close()
		return nil, errors.New("a compute system with this name already exists; refusing to replace it")
	} else if !errors.Is(openErr, hcs.ErrNotFound) {
		return nil, openErr
	}
	r := record{Owner: h.owner, Spec: spec, Phase: phaseIntent}
	if spec.Network {
		if h.net == nil {
			return nil, errors.Join(errors.New("guest networking unavailable"), h.netErr)
		}
		retained, err := h.retainedNetworks()
		if err != nil {
			return nil, err
		}
		plan, err := h.net.Plan(ctx, spec.Name, retained)
		if err != nil {
			return nil, err
		}
		r.Network = &plan
	}
	if err = h.write(recordName(spec.Name), r, true); err != nil {
		return nil, fmt.Errorf("cannot journal guest intent: %w", err)
	}
	var held system
	retain := false
	defer func() {
		if err == nil || retain {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		err = errors.Join(err, h.destroy(cleanupCtx, spec.Name, held))
	}()
	g := &Guest{Name: spec.Name}
	if err = h.root.Mkdir(spec.Name, 0o700); err != nil {
		return nil, err
	}
	if err = h.write(markerName(spec.Name), marker{Owner: h.owner, Name: spec.Name}, true); err != nil {
		return nil, err
	}
	dir := filepath.Join(h.dir, spec.Name)
	paths := []string{filepath.Join(dir, diskFile), filepath.Join(dir, guestStateFile), filepath.Join(dir, runtimeStateFile)}
	started := time.Now()
	if err = h.native.CreateDisk(paths[0], spec.Image); err != nil {
		return nil, fmt.Errorf("cannot create guest differencing disk: %w", err)
	}
	g.Timings.Disk = time.Since(started)
	started = time.Now()
	if err = h.native.CreateGuestStateFiles(paths[1], paths[2]); err != nil {
		return nil, err
	}
	g.Timings.StateFiles = time.Since(started)
	started = time.Now()
	for _, path := range paths {
		if err = h.native.GrantVMAccess(spec.Name, path); err != nil {
			return nil, err
		}
	}
	g.Timings.Grants = time.Since(started)
	if r.Network != nil {
		started = time.Now()
		if err = h.net.Create(ctx, *r.Network, spec.Name); err != nil {
			return nil, err
		}
		g.Timings.Network = time.Since(started)
	}
	r.Phase = phaseDispatched
	if err = h.write(recordName(spec.Name), r, false); err != nil {
		return nil, err
	}
	started = time.Now()
	held, err = h.native.Create(ctx, spec.Name, document(h.owner, spec, dir, r.Network))
	g.Timings.Create = time.Since(started)
	if err != nil {
		if hcs.OutcomeUnknown(err) {
			// Never replay a mutation. Recover settles it once the name is
			// observed, or once this process's handle can no longer exist.
			retain = true
			return nil, fmt.Errorf("guest create outcome unknown; record retained: %w", err)
		}
		r.Phase = phaseFailed
		return nil, errors.Join(err, h.write(recordName(spec.Name), r, false))
	}
	r.Phase = phaseCreated
	if err = h.write(recordName(spec.Name), r, false); err != nil {
		return nil, err
	}
	p, err := held.Properties(ctx)
	if err != nil {
		return nil, err
	}
	if err = h.prove(spec.Name, r, p); err != nil {
		return nil, err
	}
	// Install the port policy before the guest's first instruction when the
	// switch port already exists; otherwise immediately after start.
	if r.Network != nil {
		exists, connected, portErr := h.net.Port(ctx, *r.Network)
		if portErr != nil {
			return nil, portErr
		}
		if exists && connected {
			if err = h.protect(ctx, &r, g, ""); err != nil {
				return nil, err
			}
			g.Timings.ProtectedBeforeStart = true
		}
	}
	started = time.Now()
	if err = held.Start(ctx); err != nil {
		return nil, err
	}
	g.Timings.Start = time.Since(started)
	if p, err = held.Properties(ctx); err != nil {
		return nil, err
	}
	if err = h.prove(spec.Name, r, p); err != nil {
		return nil, err
	}
	if p.State != hcs.StateRunning || p.RuntimeID == "" {
		return nil, errors.New("guest did not report a running runtime identity")
	}
	r.RuntimeID = p.RuntimeID
	if err = h.write(recordName(spec.Name), r, false); err != nil {
		return nil, err
	}
	if r.Network != nil {
		if !g.Timings.ProtectedBeforeStart {
			if err = h.protect(ctx, &r, g, p.RuntimeID); err != nil {
				return nil, err
			}
		} else if !strings.EqualFold(strings.Trim(r.Network.VMRuntimeID, "{}"), strings.Trim(p.RuntimeID, "{}")) {
			return nil, ErrForeign
		}
		if err = h.net.Verify(ctx, *r.Network, spec.Name); err != nil {
			return nil, err
		}
		g.Network = r.Network
	}
	if spec.GPU {
		started = time.Now()
		if err = held.Modify(ctx, hcs.AssignDefaultGPU()); err != nil {
			return nil, fmt.Errorf("GPU assignment failed: %w", err)
		}
		g.Timings.GPU = time.Since(started)
	}
	g.RuntimeID = p.RuntimeID
	g.system = held
	return g, nil
}

// protect installs the port policy and journals the endpoint's committed
// runtime binding.
func (h *Host) protect(ctx context.Context, r *record, g *Guest, runtimeID string) error {
	started := time.Now()
	plan, err := h.net.Protect(ctx, *r.Network, r.Spec.Name, runtimeID)
	g.Timings.Protect = time.Since(started)
	if err != nil {
		return err
	}
	r.Network = &plan
	return h.write(recordName(r.Spec.Name), *r, false)
}

// retainedNetworks lists every journalled plan, so a new subnet never
// overlaps a network still awaiting cleanup.
func (h *Host) retainedNetworks() ([]hostnet.Plan, error) {
	entries, err := fs.ReadDir(h.root.FS(), ".")
	if err != nil {
		return nil, err
	}
	var plans []hostnet.Plan
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || entry.IsDir() || !strings.HasPrefix(name, NamePrefix) {
			continue
		}
		var r record
		if err := h.read(entry.Name(), &r); err != nil {
			return nil, err
		}
		if r.Network != nil {
			plans = append(plans, *r.Network)
		}
	}
	return plans, nil
}

// VerifyNetwork reproves a networked guest's endpoint, port policy and the
// host's effective denial. A guest without a network passes.
func (h *Host) VerifyNetwork(ctx context.Context, g *Guest) error {
	if g.Network == nil {
		return nil
	}
	return h.net.Verify(ctx, *g.Network, g.Name)
}

// BlockNetwork blocks a networked guest's port, for quarantine.
func (h *Host) BlockNetwork(ctx context.Context, g *Guest) error {
	if g.Network == nil {
		return nil
	}
	return h.net.Block(ctx, *g.Network)
}

// Running reproves that this exact guest instance is still running.
func (h *Host) Running(ctx context.Context, g *Guest) error {
	if g.system == nil {
		return errors.New("guest handle already released")
	}
	var r record
	if err := h.read(recordName(g.Name), &r); err != nil {
		return err
	}
	p, err := g.system.Properties(ctx)
	if err != nil {
		return err
	}
	if err = h.prove(g.Name, r, p); err != nil {
		return err
	}
	if p.State != hcs.StateRunning {
		return errors.New("guest is no longer running")
	}
	return nil
}

// Destroy terminates the guest through its held handle, confirms native
// absence and only then removes its storage and journal entry.
func (h *Host) Destroy(ctx context.Context, g *Guest) error {
	held := g.system
	g.system = nil
	return h.destroy(ctx, g.Name, held)
}

// Recover settles every journalled guest left by an earlier VM host. Those
// guests ended with that process, so an exact instance still present is
// terminated and an absent one has its storage removed. A running VM keeps its
// disk open, so storage still in use fails deletion and is retained.
func (h *Host) Recover(ctx context.Context) error {
	entries, err := fs.ReadDir(h.root.FS(), ".")
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || entry.IsDir() || !strings.HasPrefix(name, NamePrefix) {
			continue
		}
		if err := h.destroy(ctx, name, nil); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func (h *Host) destroy(ctx context.Context, name string, held system) error {
	if held != nil {
		defer held.Close()
	}
	var r record
	if err := h.read(recordName(name), &r); err != nil {
		return err
	}
	if r.Owner != h.owner || r.Spec.Name != name {
		return ErrForeign
	}
	var m marker
	if err := h.read(markerName(name), &m); err == nil {
		if m.Owner != h.owner || m.Name != name {
			return ErrForeign
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if r.Phase == phaseIntent || r.Phase == phaseFailed {
		// Nothing was dispatched, so any native guest by this name is foreign.
		if s, err := h.native.Open(ctx, name); err == nil {
			s.Close()
			return ErrForeign
		} else if !errors.Is(err, hcs.ErrNotFound) {
			return err
		}
		if err := h.deleteNetwork(ctx, r); err != nil {
			return err
		}
		return h.removeStorage(name)
	}
	s := held
	if s == nil {
		var err error
		if s, err = h.native.Open(ctx, name); err != nil && !errors.Is(err, hcs.ErrNotFound) {
			return err
		} else if err == nil {
			defer s.Close()
		}
	}
	if s != nil {
		p, err := s.Properties(ctx)
		if err != nil {
			return err
		}
		if err = h.prove(name, r, p); err != nil {
			return err
		}
		if p.State != hcs.StateStopped {
			if err = s.Terminate(ctx); err != nil {
				return err
			}
		}
		s.Close()
	}
	// Terminate completing is not proof of absence. Poll only this name.
	for {
		s, err := h.native.Open(ctx, name)
		if errors.Is(err, hcs.ErrNotFound) {
			break
		}
		if err == nil {
			s.Close()
		}
		select {
		case <-ctx.Done():
			return errors.New("guest absence unconfirmed; storage retained")
		case <-time.After(200 * time.Millisecond):
		}
	}
	r.Phase = phaseDeleting
	if err := h.write(recordName(name), r, false); err != nil {
		return err
	}
	if err := h.deleteNetwork(ctx, r); err != nil {
		return err
	}
	return h.removeStorage(name)
}

// deleteNetwork removes a guest's endpoint and switch once its port is gone.
// The port can outlive confirmed VM absence briefly, so it retries within ctx.
func (h *Host) deleteNetwork(ctx context.Context, r record) error {
	if r.Network == nil {
		return nil
	}
	if h.net == nil {
		return errors.Join(errors.New("guest network cleanup unavailable; retained"), h.netErr)
	}
	for {
		err := h.net.Delete(ctx, *r.Network, r.Spec.Name)
		if err == nil || errors.Is(err, hostnet.ErrForeign) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(errors.New("guest network deletion unconfirmed; retained"), err)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// removeStorage deletes only the fixed files this host creates, then the
// marker, the directory and finally the record. Unknown files fail removal.
func (h *Host) removeStorage(name string) error {
	for _, file := range []string{diskFile, guestStateFile, runtimeStateFile} {
		if err := h.root.Remove(filepath.Join(name, file)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("cannot remove guest storage: %w", err)
		}
	}
	for _, path := range []string{markerName(name), name, recordName(name) + ".new", recordName(name)} {
		if err := h.root.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("cannot remove guest journal: %w", err)
		}
	}
	return nil
}
