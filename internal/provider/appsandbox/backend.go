package appsandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/provider"
)

type NativeAPI interface {
	CreateClone(context.Context, CloneRecord, string, string) error
	VMCommand(context.Context, string, string) error
	Status(context.Context, string) (VM, error)
	SSHInfo(context.Context, string) (SSH, error)
	List(context.Context) ([]VM, error)
}

// NativeNetwork is implemented by the administrator-only Windows adapter.
// Attach begins with a blocked port; Verify reads current host/native policy,
// and Block is also used on failed verification before any runner is admitted.
type NativeNetwork interface {
	Plan(context.Context, CloneRecord, []EngineRecord) (NetworkPlan, error)
	Attach(context.Context, EngineRecord) error
	Verify(context.Context, EngineRecord) error
	Block(context.Context, EngineRecord) error
	Delete(context.Context, EngineRecord) error
}

type EngineOptions struct {
	ControllerID string
	Baseline     string
	User         string
	MaxCPU       int
	MaxMemoryMB  int
	MaxDiskGB    int
	MaxInstances int
}

// Engine serializes the shared daemon's native operations and owns a journal
// separate from the normal user's GitHub instance records. It has no GitHub
// credential, runner configuration, arbitrary command, or host disk API.
type Engine struct {
	mu            sync.Mutex
	opts          EngineOptions
	api           NativeAPI
	net           NativeNetwork
	records       *Records
	checkBaseline func(context.Context) error
	// unhealthy records that the last guard pass was incomplete (for example
	// App Sandbox was unavailable); a later full successful pass clears it.
	// policyFailed records a failed policy proof and lasts until restart.
	unhealthy    bool
	policyFailed bool
}

func NewEngine(opts EngineOptions, api NativeAPI, network NativeNetwork, records *Records, checkBaseline func(context.Context) error) (*Engine, error) {
	if opts.MaxInstances == 0 {
		opts.MaxInstances = 1
	}
	if !identifier(opts.ControllerID, 64) || !identifier(opts.Baseline, 15) || !identifier(opts.User, 32) || opts.MaxCPU < 1 || opts.MaxMemoryMB < 512 || opts.MaxDiskGB < 16 || api == nil || network == nil || records == nil || checkBaseline == nil {
		return nil, errors.New("invalid privileged App Sandbox backend")
	}
	return &Engine{opts: opts, api: api, net: network, records: records, checkBaseline: checkBaseline}, nil
}

func (e *Engine) validate(r CloneRecord) error {
	expected, err := PlanClone(e.records.path, provider.Spec{Name: r.RunnerName, Baseline: r.Template, CPU: r.CPU, MemoryMB: r.MemoryMB, Meta: r.Meta}, r.DiskGB, r.GPUMode)
	if err != nil || expected != r || r.Meta.ControllerID != e.opts.ControllerID || r.Template != e.opts.Baseline || r.CPU > e.opts.MaxCPU || r.MemoryMB > e.opts.MaxMemoryMB || r.DiskGB > e.opts.MaxDiskGB {
		return provider.ErrNotOwned
	}
	return nil
}

func (e *Engine) Create(ctx context.Context, r CloneRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.policyFailed {
		return errors.New("broker isolation guard failed; cleanup and restart are required")
	}
	if e.unhealthy {
		return errors.New("broker isolation guard incomplete; admission resumes after a full successful guard pass")
	}
	if err := e.validate(r); err != nil {
		return err
	}
	if _, err := e.records.Get(r.RunnerName); !errors.Is(err, os.ErrNotExist) {
		return errors.New("clone intent already exists; reconcile instead of retrying creation")
	}
	if _, err := e.api.Status(ctx, r.NativeName); !errors.Is(err, ErrNotFound) {
		return errors.New("cannot confirm native clone absence")
	}
	if err := e.checkBaseline(ctx); err != nil {
		return err
	}
	all, err := e.records.All()
	if err != nil {
		return err
	}
	if len(all) >= e.opts.MaxInstances {
		return errors.New("protected broker instance ceiling reached")
	}
	// Prove the parent absent before recording intent, so a later unmarked
	// parent under this record can only be the broker's own partial creation.
	if exists, err := e.records.ParentExists(r); err != nil || exists {
		return errors.New("cannot confirm instance storage parent absence")
	}
	record := EngineRecord{Clone: r, Phase: "intent"}
	if err := e.records.Put(record); err != nil {
		return err
	}
	if err := e.records.PrepareParent(r); err != nil {
		return err
	}
	record.Phase = "creating"
	record.Attempted = true
	if err := e.records.Put(record); err != nil {
		return err
	}
	password := make([]byte, 24)
	if _, err := rand.Read(password); err != nil {
		return err
	}
	err = e.api.CreateClone(ctx, r, e.opts.User, hex.EncodeToString(password)+"aA!7")
	clear(password)
	if err != nil {
		return err
	}
	// A successful request is not boot readiness; bind native identity now and
	// retain intent if anything after acceptance cannot be verified.
	if _, err = e.lookup(ctx, r.RunnerName, true); err != nil {
		return err
	}
	record.Phase = "created"
	return e.records.Put(record)
}

func (e *Engine) lookup(ctx context.Context, name string, recoverChild bool) (Lease, error) {
	r, err := e.records.Get(name)
	if errors.Is(err, os.ErrNotExist) {
		return Lease{}, provider.ErrNotFound
	}
	if err != nil {
		return Lease{}, err
	}
	if err = e.validate(r.Clone); err != nil {
		return Lease{}, err
	}
	parent, err := e.records.Parent(r.Clone)
	if err != nil || parent != r.Clone {
		// An intent can fail before marking its parent, and a deletion can
		// stop after removing the marker or parent but before the record.
		// Only confirmed native and child absence permits finishing that
		// cleanup; it must never claim a live instance.
		if cleanupPhase(r.Phase) && errors.Is(err, os.ErrNotExist) {
			if _, nativeErr := e.api.Status(ctx, r.Clone.NativeName); errors.Is(nativeErr, ErrNotFound) {
				if exists, childErr := e.records.ChildExists(r.Clone); childErr == nil && !exists {
					return Lease{Record: r.Clone}, nil
				}
			}
		}
		return Lease{}, provider.ErrNotOwned
	}
	vm, err := e.api.Status(ctx, r.Clone.NativeName)
	if errors.Is(err, ErrNotFound) {
		return Lease{Record: r.Clone}, nil
	}
	if err != nil {
		return Lease{}, err
	}
	child, err := e.records.Child(r.Clone)
	if errors.Is(err, os.ErrNotExist) && recoverChild && r.Phase == "creating" && r.Attempted {
		// Only protected, prior dispatch intent plus exact native metadata can
		// finish a marker after a crash/unknown create response. No name adoption.
		if err = CheckClone(e.records.path, e.opts.ControllerID, r.Clone, parent, r.Clone, vm); err == nil {
			err = e.records.MarkChild(r.Clone)
			child = r.Clone
		}
	}
	if err != nil {
		return Lease{}, provider.ErrNotOwned
	}
	if err = CheckClone(e.records.path, e.opts.ControllerID, r.Clone, parent, child, vm); err != nil {
		return Lease{}, err
	}
	l := Lease{Record: r.Clone, VM: vm}
	if r.Network != nil {
		l.Address = r.Network.Address
		l.Gateway = r.Network.Gateway
		l.Prefix = 28
		l.MAC = r.Network.MAC
	}
	if vm.AgentOnline && vm.InstallComplete && !vm.Building {
		l.SSH, err = e.api.SSHInfo(ctx, r.Clone.NativeName)
		if err != nil {
			return Lease{}, err
		}
		if l.SSH.User != e.opts.User {
			return Lease{}, provider.ErrNotOwned
		}
	}
	return l, nil
}

func (e *Engine) Lookup(ctx context.Context, name string) (Lease, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lookup(ctx, name, true)
}
func (e *Engine) Start(ctx context.Context, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	l, err := e.lookup(ctx, name, true)
	if err != nil {
		return err
	}
	if l.VM.Name == "" {
		return provider.ErrNotFound
	}
	if l.VM.Running || l.VM.Building {
		return nil
	}
	r, err := e.records.Get(name)
	if err != nil {
		return err
	}
	// App Sandbox cannot persist our external adapter across a native reboot.
	// Never start an old network binding or silently reuse its port.
	if r.Network != nil {
		return errors.New("networked guest stopped; discard it instead of restarting")
	}
	return e.api.VMCommand(ctx, l.Record.NativeName, "start")
}
func (e *Engine) Prepare(ctx context.Context, name string) (Lease, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	l, err := e.lookup(ctx, name, true)
	if err != nil {
		return Lease{}, err
	}
	if !l.VM.Running || !l.VM.AgentOnline || !l.VM.InstallComplete || l.VM.Building || !l.SSH.ForwardReady() {
		return Lease{}, errors.New("owned guest is not ready for networking")
	}
	r, err := e.records.Get(name)
	if err != nil {
		return Lease{}, err
	}
	if r.Network != nil {
		if r.Phase != "ready" {
			return Lease{}, errors.New("partial network creation requires cleanup")
		}
		if err = e.verify(ctx, r); err != nil {
			return Lease{}, err
		}
		return e.lookup(ctx, name, false)
	}
	all, err := e.records.All()
	if err != nil {
		return Lease{}, err
	}
	network, err := e.net.Plan(ctx, r.Clone, all)
	if err != nil {
		return Lease{}, err
	}
	r.Network = &network
	r.Phase = "networking"
	if err = e.records.Put(r); err != nil {
		return Lease{}, err
	}
	if err = e.net.Attach(ctx, r); err != nil {
		blockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return Lease{}, errors.Join(err, e.net.Block(blockCtx, r))
	}
	if err = e.verify(ctx, r); err != nil {
		return Lease{}, err
	}
	r.Phase = "ready"
	if err = e.records.Put(r); err != nil {
		return Lease{}, err
	}
	return e.lookup(ctx, name, false)
}
func (e *Engine) verify(ctx context.Context, r EngineRecord) error {
	if r.Network == nil {
		return errors.New("owned guest has no isolated network")
	}
	if err := e.net.Verify(ctx, r); err != nil {
		// Do not leave a connected guest using a stale or weakened policy.
		blockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return errors.Join(err, e.net.Block(blockCtx, r))
	}
	return nil
}
func (e *Engine) Verify(ctx context.Context, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	l, err := e.lookup(ctx, name, false)
	if err != nil {
		return err
	}
	if !l.VM.Running || l.VM.Name == "" {
		return errors.New("isolated native guest unavailable")
	}
	r, err := e.records.Get(name)
	if err != nil {
		return err
	}
	if r.Phase != "ready" {
		return errors.New("isolated network not committed")
	}
	return e.verify(ctx, r)
}
func (e *Engine) stop(ctx context.Context, l Lease, timeout time.Duration) error {
	if l.VM.Name == "" || (!l.VM.Running && !l.VM.Building) {
		return nil
	}
	if timeout > 0 {
		if err := e.api.VMCommand(ctx, l.Record.NativeName, "shutdown"); err != nil && !errors.Is(err, ErrOutcomeUnknown) {
			return err
		}
		deadline := time.Now().Add(min(timeout, 30*time.Second))
		for time.Now().Before(deadline) {
			current, err := e.lookup(ctx, l.Record.RunnerName, true)
			if err != nil {
				return err
			}
			if current.VM.Name == "" || (!current.VM.Running && !current.VM.Building) {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	if _, err := e.lookup(ctx, l.Record.RunnerName, true); err != nil {
		return err
	}
	if err := e.api.VMCommand(ctx, l.Record.NativeName, "stop"); err != nil {
		return err
	}
	current, err := e.lookup(ctx, l.Record.RunnerName, true)
	if err != nil {
		return err
	}
	if current.VM.Running || current.VM.Building {
		return errors.New("owned guest still running after stop")
	}
	return nil
}
func (e *Engine) Stop(ctx context.Context, name string, timeout time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	l, err := e.lookup(ctx, name, true)
	if err != nil {
		return err
	}
	return e.stop(ctx, l, timeout)
}
func (e *Engine) Delete(ctx context.Context, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	l, err := e.lookup(ctx, name, true)
	if errors.Is(err, provider.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	r, err := e.records.Get(name)
	if err != nil {
		return err
	}
	if err = e.stop(ctx, l, 0); err != nil {
		return err
	}
	l, err = e.lookup(ctx, name, true)
	if err != nil {
		return err
	}
	if l.VM.Name != "" {
		if err = e.api.VMCommand(ctx, r.Clone.NativeName, "delete"); err != nil {
			return err
		}
		if _, err = e.api.Status(ctx, r.Clone.NativeName); !errors.Is(err, ErrNotFound) {
			return errors.New("native VM deletion unconfirmed")
		}
	}
	if exists, err := e.records.ChildExists(r.Clone); err != nil {
		return err
	} else if exists {
		return errors.New("native storage deletion unconfirmed")
	}
	// A retry after a crash in Remove resumes there; network cleanup is
	// already confirmed. Network deletion itself is idempotent.
	if r.Phase != "network_deleted" {
		r.Phase = "native_deleted"
		if err = e.records.Put(r); err != nil {
			return err
		}
		if r.Network != nil {
			if err = e.net.Delete(ctx, r); err != nil {
				return err
			}
		}
		r.Phase = "network_deleted"
		if err = e.records.Put(r); err != nil {
			return err
		}
	}
	return e.records.Remove(r)
}
func (e *Engine) List(ctx context.Context) ([]provider.Owned, []provider.Foreign, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	records, err := e.records.All()
	if err != nil {
		return nil, nil, err
	}
	known := map[string]bool{}
	var owned []provider.Owned
	var foreign []provider.Foreign
	for _, r := range records {
		known[r.Clone.NativeName] = true
		l, err := e.lookup(ctx, r.Clone.RunnerName, true)
		if err != nil {
			// One unprovable record must not hide the rest of the inventory.
			// Report it as a prefixed foreign guest holding a slot: callers
			// never touch it, and its native VM is not counted twice.
			foreign = append(foreign, provider.Foreign{Name: r.Clone.RunnerName, Running: true, Prefixed: true})
			continue
		}
		owned = append(owned, provider.Owned{Name: l.Record.RunnerName, Running: l.VM.Running, Meta: l.Record.Meta})
	}
	vms, err := e.api.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, vm := range vms {
		if !known[vm.Name] {
			foreign = append(foreign, provider.Foreign{Name: vm.Name, Running: vm.Running || vm.Building, Prefixed: strings.HasPrefix(vm.Name, "bivouac-")})
		}
	}
	return owned, foreign, nil
}

// Root reports only storage metadata; it grants no authority to delete paths.
func (e *Engine) Root() string { return filepath.Clean(e.records.path) }

// Guard checks policy independently of the normal-user manager. A failed
// proof quarantines the guest; a failed port block also stops the owned VM.
// It never repairs or silently resumes a running guest.
func (e *Engine) Guard(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	all, err := e.records.All()
	if err != nil {
		e.unhealthy = true
		return err
	}
	var failures []error
	for _, r := range all {
		if r.Network == nil || r.Phase == "native_deleted" || r.Phase == "network_deleted" {
			continue
		}
		l, lookupErr := e.lookup(ctx, r.Clone.RunnerName, true)
		if lookupErr != nil {
			// App Sandbox may be unavailable or the native identity unprovable.
			// The switch, endpoint and port are journalled by GUID, so policy is
			// still verified and blocked without the App Sandbox API. Only a VM
			// whose identity was proven may be stopped below.
			failures = append(failures, lookupErr)
		} else if l.VM.Name == "" || !l.VM.Running {
			continue
		}
		verifyErr := errors.New("incomplete or quarantined native network")
		if r.Phase == "ready" {
			verifyErr = e.net.Verify(ctx, r)
		}
		if verifyErr == nil {
			continue
		}
		e.policyFailed = true
		blockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		blockErr := e.net.Block(blockCtx, r)
		if blockErr != nil && lookupErr == nil {
			blockErr = errors.Join(blockErr, e.stop(blockCtx, l, 0))
		}
		cancel()
		r.Phase = "quarantined"
		failures = append(failures, verifyErr, blockErr, e.records.Put(r))
	}
	err = errors.Join(failures...)
	// An incomplete pass blocks admission until a later pass succeeds in full;
	// policyFailed stays set regardless.
	e.unhealthy = err != nil
	return err
}
