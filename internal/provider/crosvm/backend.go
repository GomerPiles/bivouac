package crosvm

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/command"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/provider"
)

type NativeBackend struct {
	mu       sync.Mutex
	opts     Options
	lock     *control.Lock
	commands command.Native
	// alive proves whether a recorded native process still exists.
	alive func(ProcessIdentity) (bool, error)
}

// stagingPrefix names a new instance directory before both ownership markers
// exist. It is renamed into place only once complete and never holds a disk.
const stagingPrefix = ".creating-"

func OpenBackend(opts Options) (*NativeBackend, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New("native Crosvm backend requires Windows")
	}
	return openBackend(opts, sameProcess)
}

func openBackend(opts Options, alive func(ProcessIdentity) (bool, error)) (*NativeBackend, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opts.Root, 0o700); err != nil {
		return nil, err
	}
	opts, err := opts.Canonical()
	if err != nil {
		return nil, err
	}
	lock, err := (control.Files{Dir: opts.Root}).Acquire()
	if err != nil {
		return nil, err
	}
	b := &NativeBackend{opts: opts, lock: lock, alive: alive}
	if err := b.pinConfiguration(); err != nil {
		b.Close()
		return nil, err
	}
	if err := b.sweepStaging(); err != nil {
		b.Close()
		return nil, err
	}
	return b, nil
}

// Options returns the canonical options this backend froze. Callers pass them
// to New so that provider-side launch checks match recorded instances.
func (b *NativeBackend) Options() Options { return b.opts }

func (b *NativeBackend) Close() {
	if b.lock != nil {
		_ = b.lock.Release()
		b.lock = nil
	}
}

// Each instance envelope pins its own Options, so the root record only guards
// retained instances. It may change while no instance directory exists.
func (b *NativeBackend) pinConfiguration() error {
	var previous Options
	err := readJSON(filepath.Join(b.opts.Root, "provider.json"), &previous)
	if err == nil && b.accepts(previous) {
		if reflect.DeepEqual(previous, b.opts) {
			return nil
		}
		return writeJSON(b.opts.Root, "provider.json", b.opts)
	}
	retained, countErr := b.directories()
	if countErr != nil {
		return countErr
	}
	if retained != 0 {
		return errors.New("crosvm root belongs to another configuration; finish cleanup of retained instances first")
	}
	return writeJSON(b.opts.Root, "provider.json", b.opts)
}

// directories counts every retained instance, staging or unverifiable
// directory. Each one keeps its disk reservation and pins the root.
func (b *NativeBackend) directories() (uint64, error) {
	entries, err := os.ReadDir(b.opts.Root)
	if err != nil {
		return 0, err
	}
	count := uint64(0)
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}
	return count, nil
}

// sweepStaging removes directories left by a Create that crashed before its
// rename. Under the exclusive root lock no Create is in progress. Staging never
// holds a disk or process, so only marker files may be removed; anything else
// retains the directory for inspection.
func (b *NativeBackend) sweepStaging() error {
	entries, err := os.ReadDir(b.opts.Root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		id, ok := strings.CutPrefix(entry.Name(), stagingPrefix)
		if entry.IsDir() && ok && validID(id) {
			_ = removeStaging(filepath.Join(b.opts.Root, entry.Name()))
		}
	}
	return nil
}

func stagingFiles() []string {
	return []string{"owner.json.new", ".bivouac-owner.json.new", "owner.json", ".bivouac-owner.json"}
}

func removeStaging(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !slices.Contains(stagingFiles(), entry.Name()) || !entry.Type().IsRegular() {
			return errors.New("unexpected file in instance staging directory")
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	for _, file := range stagingFiles() {
		if err := root.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = root.Close()
			return err
		}
	}
	_ = root.Close()
	return os.Remove(directory)
}

// createInstanceDirectory publishes a directory that already carries both
// ownership markers. A crash leaves either nothing or a sweepable staging
// directory, never an unmarked instance directory.
func createInstanceDirectory(root string, e Envelope) error {
	if _, err := os.Lstat(e.Record.Directory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("instance directory already exists or cannot be created")
	}
	staging := filepath.Join(root, stagingPrefix+e.Record.Meta.InstanceID)
	if err := os.Mkdir(staging, 0o700); err != nil {
		return errors.New("instance staging directory already exists or cannot be created")
	}
	err := writeJSON(staging, "owner.json", e)
	if err == nil {
		err = writeJSON(staging, ".bivouac-owner.json", e.Record)
	}
	if err == nil {
		err = os.Rename(staging, e.Record.Directory)
	}
	if err != nil {
		return errors.Join(err, removeStaging(staging))
	}
	return nil
}

func validID(id string) bool {
	return len(id) == 8 && strings.Trim(id, "0123456789abcdef") == ""
}

// CheckLocal checks launch prerequisites without starting a VM or reading the
// raw baseline's contents.
func (b *NativeBackend) CheckLocal() error {
	if err := b.reserveDisk(); err != nil {
		return err
	}
	if err := verifySetupInputs(b.opts); err != nil {
		return err
	}
	_, _, err := inventory()
	return err
}

// accepts reports whether recorded options are this backend's configuration.
// Records written before canonicalization hold paths as configured (another
// case, 8.3 short names, a symlink or junction); their canonical form must
// match the frozen options exactly.
func (b *NativeBackend) accepts(recorded Options) bool {
	if reflect.DeepEqual(recorded, b.opts) {
		return true
	}
	canonical, err := recorded.Canonical()
	return err == nil && reflect.DeepEqual(canonical, b.opts)
}

func (b *NativeBackend) envelope(name string) (Envelope, error) {
	current, _, err := b.owned(name)
	return current, err
}

// owned loads an instance's envelope. current is expressed in the canonical
// options, so provider launch checks and native image comparisons match;
// recorded is the envelope as written, which the supervisor reloads and a
// failed Delete restores unchanged.
func (b *NativeBackend) owned(name string) (current, recorded Envelope, err error) {
	if !strings.HasPrefix(name, "bivouac-"+b.opts.Name+"-") {
		return Envelope{}, Envelope{}, provider.ErrNotOwned
	}
	id := name[strings.LastIndexByte(name, '-')+1:]
	if !validID(id) {
		return Envelope{}, Envelope{}, provider.ErrNotOwned
	}
	recorded, err = readEnvelope(filepath.Join(b.opts.Root, id, "owner.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Envelope{}, Envelope{}, provider.ErrNotFound
	}
	if err != nil {
		return recorded, recorded, err
	}
	if recorded.Record.Name != name || recorded.Record.Meta.InstanceID != id || !b.accepts(recorded.Options) {
		return recorded, recorded, provider.ErrNotOwned
	}
	// readEnvelope proved every record path derives from the recorded options
	// (the directory is <root>/<id>), and those canonicalize to ours, so the
	// same plan over the canonical options names the same files. Launch
	// confirms nothing else differs.
	r := recorded.Record
	r.Directory = filepath.Join(b.opts.Root, id)
	r.Disk = filepath.Join(r.Directory, "disk.qcow2")
	r.Binary, r.Baseline = b.opts.Binary, b.opts.Baseline
	if _, _, err := Launch(b.opts, r); err != nil {
		return recorded, recorded, provider.ErrNotOwned
	}
	return Envelope{Options: b.opts, Record: r}, recorded, nil
}
func (b *NativeBackend) Create(ctx context.Context, spec provider.Spec) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.reserveDisk(); err != nil {
		return err
	}
	if err := verifyLaunchInputs(b.opts); err != nil {
		return err
	}
	prefixes, snapshot, err := inventory()
	if err != nil {
		return err
	}
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	port := 20000 + (int(random[0])<<8|int(random[1]))%30000
	listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return errors.New("selected loopback port is unavailable")
	}
	_ = listener.Close()
	record, err := Plan(b.opts, spec, port, prefixes, snapshot)
	if err != nil {
		return err
	}
	if err := createInstanceDirectory(b.opts.Root, Envelope{Options: b.opts, Record: record}); err != nil {
		return err
	}
	_, err = b.commands.Output(ctx, b.opts.QemuImg, []string{"create", "-f", "qcow2", "-F", "raw", "-b", record.Baseline, record.Disk})
	if err != nil {
		return err
	}
	return b.disk(ctx, record)
}

// Conservative admission reserves a complete disk's possible growth for every
// retained instance, plus QCOW metadata, both capped native logs and 16 GiB for
// the physical host. Existing allocated overlay bytes are intentionally not
// subtracted from the reservation.
func (b *NativeBackend) reserveDisk() error {
	size, err := rawBaselineSize(b.opts.Baseline)
	if err != nil {
		return err
	}
	retained, err := b.directories()
	if err != nil {
		return err
	}
	count := retained + 1
	if count > 1024 {
		return errors.New("too many retained native disk reservations")
	}
	available, err := diskCapacity(b.opts.Root)
	if err != nil {
		return err
	}
	perDisk := size + size/32 + 1<<30 + logReserve
	if available < perDisk*count+16<<30 {
		return errors.New("insufficient free disk for retained and new overlay growth plus host reserve")
	}
	return nil
}

// ExerciseSupervisorLoss is restricted to the explicit local validation path.
// It has no runner token input and never searches for an unrecorded process.
func (b *NativeBackend) ExerciseSupervisorLoss(ctx context.Context, name string) error {
	if err := b.Verify(ctx, name); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e, err := b.envelope(name)
	if err != nil {
		return err
	}
	var native NativeState
	if err := readJSON(filepath.Join(e.Record.Directory, "native.json"), &native); err != nil {
		return err
	}
	var dispatch ProcessIdentity
	if err := readJSON(filepath.Join(e.Record.Directory, "dispatch.json"), &dispatch); err != nil {
		return err
	}
	if !native.JobOwned || native.Phase != "running" || native.Supervisor != dispatch {
		return provider.ErrNotOwned
	}
	return terminateRecorded(native.Supervisor)
}
func (b *NativeBackend) disk(ctx context.Context, r Record) error {
	data, err := b.commands.Output(ctx, b.opts.QemuImg, []string{"info", "--output=json", r.Disk})
	if err != nil {
		return err
	}
	var metadata struct {
		Format        string `json:"format"`
		Backing       string `json:"full-backing-filename"`
		BackingFormat string `json:"backing-filename-format"`
	}
	if json.Unmarshal(data, &metadata) != nil || metadata.Format != "qcow2" || metadata.BackingFormat != "raw" || !sameBacking(metadata.Backing, r.Baseline) {
		return provider.ErrNotOwned
	}
	return nil
}

// sameBacking compares an overlay's backing path with the frozen baseline. An
// overlay created before canonicalization names the baseline as configured,
// so a path that differs is resolved the way Canonical resolves the baseline.
func sameBacking(backing, baseline string) bool {
	if strings.EqualFold(filepath.Clean(backing), filepath.Clean(baseline)) {
		return true
	}
	resolved, err := resolvePath(backing)
	return err == nil && strings.EqualFold(filepath.Clean(resolved), filepath.Clean(baseline))
}
func (b *NativeBackend) Start(ctx context.Context, name string, out io.Writer) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	envelope, recorded, err := b.owned(name)
	if err != nil {
		return err
	}
	r := envelope.Record
	if err := b.disk(ctx, r); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(r.Directory, "launch.intent")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("native launch already attempted; reconcile instead of retrying")
	}
	if err := writeJSON(r.Directory, "launch.intent", struct {
		Attempted bool `json:"attempted"`
	}{true}); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	// The supervisor reloads the envelope as written; loadEnvelope requires its
	// path to match the recorded directory.
	process, detached, err := startSupervisor(self, "crosvm", "supervise", "--record", filepath.Join(recorded.Record.Directory, "owner.json"))
	if err != nil {
		return errors.Join(err, writeJSON(r.Directory, "native.json", NativeState{Phase: "failed", Empty: true}))
	}
	// The open process handle pins the PID until its identity is journalled;
	// release it on every path so no handle outlives this dispatch.
	defer func() { _ = process.Release() }()
	if process.Pid < 1 || uint64(process.Pid) > 0xffffffff {
		return errors.New("invalid supervisor PID after dispatch")
	}
	identity, live, err := Identity(uint32(process.Pid))
	if err != nil || !live {
		return errors.New("supervisor dispatch outcome unknown; retain the launch intent")
	}
	if err := writeJSON(r.Directory, "dispatch.json", identity); err != nil {
		return err
	}
	if !detached {
		if _, err := io.WriteString(out, "Crosvm supervisor could not leave the controller's job object; closing that job also stops this VM\n"); err != nil {
			return err
		}
	}
	_, err = io.WriteString(out, "Crosvm owned Linux supervisor started with fixed public-only networking\n")
	return err
}
func (b *NativeBackend) Lookup(_ context.Context, name string) (Record, provider.Status, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lookup(name)
}

func (b *NativeBackend) lookup(name string) (Record, provider.Status, error) {
	envelope, err := b.envelope(name)
	if err != nil {
		return Record{}, provider.Status{}, err
	}
	r := envelope.Record
	status := provider.Status{Exists: true, Owned: true, Meta: r.Meta}
	var state NativeState
	if err := readJSON(filepath.Join(r.Directory, "native.json"), &state); errors.Is(err, os.ErrNotExist) {
		return r, status, nil
	} else if err != nil {
		return r, status, err
	}
	if state.Supervisor.PID != 0 {
		live, err := b.alive(state.Supervisor)
		if err != nil {
			return r, status, err
		}
		if live && state.Phase == "running" {
			vmLive, err := b.alive(state.VM)
			if err != nil {
				return r, status, err
			}
			status.Running = vmLive
		}
	}
	return r, status, nil
}
func (b *NativeBackend) Verify(ctx context.Context, name string) error {
	r, status, err := b.Lookup(ctx, name)
	if err != nil {
		return err
	}
	if !status.Running {
		return errors.New("owned Linux VM or supervisor unavailable")
	}
	return verifyInventory(r)
}
func (b *NativeBackend) WaitReady(ctx context.Context, name string) (Record, error) {
	for {
		r, status, err := b.Lookup(ctx, name)
		if err != nil {
			return r, err
		}
		if status.Running {
			if err := b.Verify(ctx, name); err != nil {
				return r, err
			}
			probe, cancel := context.WithTimeout(ctx, 2*time.Second)
			connection, err := (&net.Dialer{}).DialContext(probe, "tcp4", "127.0.0.1:"+strconv.Itoa(r.SSHPort))
			if err == nil {
				_ = connection.SetReadDeadline(time.Now().Add(time.Second))
				banner, readErr := bufio.NewReader(io.LimitReader(connection, 256)).ReadString('\n')
				_ = connection.Close()
				cancel()
				if readErr == nil && strings.HasPrefix(banner, "SSH-2.0-") {
					return r, nil
				}
			} else {
				cancel()
			}
		}
		select {
		case <-ctx.Done():
			return Record{}, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// abandonLaunch resolves a launch intent without native state: Start crashed
// before or during dispatch, or the supervisor exited before journalling. The
// stop marker makes a supervisor that has not yet journalled exit without
// launching, and the instance lock it holds for its whole life proves none is
// between those steps. A dispatched supervisor that has not yet taken the lock
// is still alive under its dispatch identity; wait for it to exit. The failed
// state then makes the launch single-use.
func (b *NativeBackend) abandonLaunch(r Record) error {
	pending := errors.New("native launch is pending or unconfirmed; retaining the overlay")
	if err := os.WriteFile(filepath.Join(r.Directory, "stop"), []byte("stop"), 0o600); err != nil {
		return err
	}
	var dispatch ProcessIdentity
	if err := readJSON(filepath.Join(r.Directory, "dispatch.json"), &dispatch); err == nil {
		live, err := b.alive(dispatch)
		if err != nil {
			return err
		}
		if live {
			return pending
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lock, err := (control.Files{Dir: r.Directory}).Acquire()
	if err != nil {
		return pending
	}
	defer func() { _ = lock.Release() }()
	var state NativeState
	if err := readJSON(filepath.Join(r.Directory, "native.json"), &state); !errors.Is(err, os.ErrNotExist) {
		return errors.New("native supervisor journalled during stop; retry")
	}
	return writeJSON(r.Directory, "native.json", NativeState{Phase: "failed", Empty: true})
}

func (b *NativeBackend) Stop(ctx context.Context, name string, _ time.Duration) error {
	b.mu.Lock()
	envelope, err := b.envelope(name)
	if err != nil {
		b.mu.Unlock()
		return err
	}
	r := envelope.Record
	var state NativeState
	if err := readJSON(filepath.Join(r.Directory, "native.json"), &state); errors.Is(err, os.ErrNotExist) {
		// Hold the backend lock so a concurrent Start cannot dispatch meanwhile.
		defer b.mu.Unlock()
		if _, intentErr := os.Stat(filepath.Join(r.Directory, "launch.intent")); errors.Is(intentErr, os.ErrNotExist) {
			return nil
		} else if intentErr != nil {
			return intentErr
		}
		return b.abandonLaunch(r)
	} else if err != nil {
		b.mu.Unlock()
		return err
	}
	b.mu.Unlock()
	if state.Supervisor.PID == 0 {
		if state.Empty && state.Phase == "failed" {
			return nil
		}
		return errors.New("native supervisor identity is missing; retaining overlay")
	}
	live, err := b.alive(state.Supervisor)
	if err != nil {
		return err
	}
	if live {
		if err := os.WriteFile(filepath.Join(r.Directory, "stop"), []byte("stop"), 0o600); err != nil {
			return err
		}
		for {
			state = NativeState{}
			if err := readJSON(filepath.Join(r.Directory, "native.json"), &state); err != nil {
				return err
			}
			if state.Empty && state.Phase == "exited" {
				break
			}
			live, err := b.alive(state.Supervisor)
			if err != nil {
				return err
			}
			if !live {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	if !state.Empty {
		if !state.JobOwned {
			return errors.New("native job ownership unconfirmed; retaining overlay")
		}
		// No live supervisor can create more children. Its durable job marker
		// permits a native query/termination of this one recorded process group.
		if err := recoverJob(ctx, r); err != nil {
			return err
		}
		if state.VM.PID != 0 {
			if !sameImage(state.VM.Image, r.Binary) {
				return provider.ErrNotOwned
			}
			for {
				live, err := b.alive(state.VM)
				if err != nil {
					return err
				}
				if !live {
					break
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(100 * time.Millisecond):
				}
			}
		}
		state.Phase, state.Empty = "exited", true
		return writeJSON(r.Directory, "native.json", state)
	}
	return nil
}

// instanceFiles are the only files Delete removes before the markers: the
// overlay, logs, journals and any temporary file an interrupted writeJSON left.
// native.json goes last, so a stalled supervisor still sees a used launch.
func instanceFiles() []string {
	return []string{"image-shutdown.json", "image-shutdown.json.new", "disk.qcow2", "stop", "serial.log", "native.log", "daemon.lock", "launch.intent", "dispatch.json",
		"launch.intent.new", "dispatch.json.new", "native.json.new", "owner.json.new", ".bivouac-owner.json.new", "native.json"}
}

func (b *NativeBackend) Delete(ctx context.Context, name string) error {
	if err := b.Stop(ctx, name, 0); errors.Is(err, provider.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	envelope, recorded, err := b.owned(name)
	if errors.Is(err, provider.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	r := envelope.Record
	var state NativeState
	err = readJSON(filepath.Join(r.Directory, "native.json"), &state)
	if err == nil {
		if !state.Empty || (state.Phase != "exited" && state.Phase != "failed") {
			return errors.New("native child exit unconfirmed; retaining overlay")
		}
		for _, identity := range []ProcessIdentity{state.Supervisor, state.VM} {
			if identity.PID == 0 {
				continue
			}
			live, err := b.alive(identity)
			if err != nil {
				return err
			}
			if live {
				return errors.New("owned native process still exists")
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(r.Disk); err == nil {
		if err := b.disk(ctx, r); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	root, err := os.OpenRoot(r.Directory)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	for _, file := range instanceFiles() {
		if err := root.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// Markers are removed only after all known resources are absent. Unexpected
	// files retain ownership, rather than authorizing recursive deletion.
	entries, err := os.ReadDir(r.Directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "owner.json" && entry.Name() != ".bivouac-owner.json" {
			return errors.New("unexpected instance files; retaining ownership markers")
		}
	}
	// If any final unlink fails, put both independent ownership records back.
	// A retry must not lose authority halfway through deleting the markers.
	complete := false
	defer func() {
		if !complete {
			_ = writeJSON(r.Directory, "owner.json", recorded)
			_ = writeJSON(r.Directory, ".bivouac-owner.json", recorded.Record)
		}
	}()
	if err := root.Remove(".bivouac-owner.json"); err != nil {
		return err
	}
	if err := root.Remove("owner.json"); err != nil {
		return err
	}
	_ = root.Close()
	if err := os.Remove(r.Directory); err != nil {
		return err
	}
	complete = true
	return nil
}

// List never fails because one entry is unverifiable. Such directories, and
// staging left by an interrupted Create, are reported as prefixed foreign
// entries: shown as unmanaged, never stopped or deleted, and still counted by
// disk admission. Only fully verified envelopes are returned as owned.
func (b *NativeBackend) List(context.Context) ([]provider.Owned, []provider.Foreign, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entries, err := os.ReadDir(b.opts.Root)
	if err != nil {
		return nil, nil, err
	}
	var owned []provider.Owned
	var foreign []provider.Foreign
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if validID(name) {
			name = "bivouac-" + b.opts.Name + "-" + name
			r, status, err := b.lookup(name)
			if err == nil {
				owned = append(owned, provider.Owned{Name: r.Name, Meta: r.Meta, Running: status.Running})
				continue
			}
		}
		// Its state is unknown, so it is conservatively treated as running.
		foreign = append(foreign, provider.Foreign{Name: name, Running: true, Prefixed: true})
	}
	return owned, foreign, nil
}
