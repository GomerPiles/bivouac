// Package manager is bivouac's portable core: the control-mode loop, the
// per-provider demand pollers, the instance lifecycle state machine, budgets,
// recovery, and the status snapshot.
package manager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/diag"
	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/hostinfo"
	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

// Options wires the manager.
type Options struct {
	Cache     *cache.Service
	Config    *config.Config
	Store     *state.Store
	Files     control.Files
	Providers map[string]provider.Provider
	GitHub    github.ScaleSets
	JIT       github.JITRunners
	Host      hostinfo.Info
	Log       *slog.Logger
	// LogDir receives per-instance launch logs; DiagDir the diagnostics.
	LogDir  string
	DiagDir string
	// Wake delivers operator nudges (the CLI's signal).
	Wake <-chan struct{}
	// NewID makes unique instance IDs.
	NewID func() string
	// PollInterval is how often guests are asked about their runner; tests
	// shorten it. Default 2s.
	PollInterval time.Duration
	// RunnerStatusGrace bounds consecutive guest transport failures. Default 60s.
	RunnerStatusGrace time.Duration
	// RunnerStatusTimeout bounds each status probe. Default 15s.
	RunnerStatusTimeout time.Duration
	// Tick is the control loop's idle period. Default 1s.
	Tick time.Duration
	// SurplusGrace is how long an idle registered runner is kept once the
	// scale set reports fewer assigned jobs than runners. Default 30s.
	SurplusGrace time.Duration
	// CleanupRetry is the delay before retrying retained teardown records.
	// Default 5s; the guest is already gone while GitHub may still be busy.
	CleanupRetry time.Duration
	// UnownedRetryMax caps the backoff for a record whose guest exists without
	// our metadata; such a record never blocks off from exiting. Default 5m.
	UnownedRetryMax time.Duration
	// DiagTimeout bounds diagnostics collection during teardown. Default 60s.
	DiagTimeout time.Duration
	// ProviderTimeout bounds each other provider and GitHub call made by
	// teardown and the control loop. Default 2m. A provider whose
	// Capabilities.OperationTimeout is longer gets that bound for Status,
	// Stop and Delete.
	ProviderTimeout time.Duration
	// NoSweep disables the sweep runner started after a session opens or a
	// label-matched job is detected. Tests use it.
	NoSweep bool
}

// Manager runs the daemon.
type Manager struct {
	o Options

	admissionMu  sync.Mutex // capacity check and durable reservation across pollers
	mu           sync.Mutex
	root         context.Context // Run's context; instance lifecycles hang off it, not off a poller
	accepting    atomic.Bool     // mode is on: capacity may be offered and guests launched
	runs         map[string]*run // active instance goroutines by instance ID
	pollers      map[string]*poller
	events       chan struct{}
	phase        string
	wg           sync.WaitGroup
	poolRetry    map[string]time.Time
	runtimes     map[string]runtimeState // guarded by mu; separate from pool retries
	previousMode control.Mode            // guarded by mu; last mode observed by the loop
}

type run struct {
	inst   *state.Instance
	cancel context.CancelFunc
	// stopNow asks the run to abandon the job immediately (stop mode).
	stopNow chan struct{}
	once    sync.Once
	// parked marks a teardown that can only wait for an operator: the guest
	// exists without our metadata. It does not keep drain, stop or off busy.
	parked atomic.Bool
}

// stopRequested reports whether stop mode or surplus retirement asked this
// run to end now.
func (r *run) stopRequested() bool {
	select {
	case <-r.stopNow:
		return true
	default:
		return false
	}
}

// New validates options and returns a manager.
func New(o Options) (*Manager, error) {
	if o.Config == nil || o.Store == nil || o.Log == nil || o.NewID == nil {
		return nil, errors.New("manager: incomplete options")
	}
	if o.Config.GitHub.Demand == config.DemandJIT && o.JIT == nil || o.Config.GitHub.Demand == config.DemandScaleSet && o.GitHub == nil {
		return nil, errors.New("manager: missing demand client")
	}
	for name := range o.Config.Providers {
		if _, ok := o.Providers[name]; !ok {
			return nil, fmt.Errorf("manager: no provider implementation for %q", name)
		}
	}
	if o.PollInterval == 0 {
		o.PollInterval = 2 * time.Second
	}
	if o.RunnerStatusGrace == 0 {
		o.RunnerStatusGrace = time.Minute
	}
	if o.RunnerStatusTimeout == 0 {
		o.RunnerStatusTimeout = 15 * time.Second
	}
	if o.Tick == 0 {
		o.Tick = time.Second
	}
	if o.SurplusGrace == 0 {
		o.SurplusGrace = 30 * time.Second
	}
	if o.CleanupRetry == 0 {
		o.CleanupRetry = 5 * time.Second
	}
	if o.UnownedRetryMax == 0 {
		o.UnownedRetryMax = 5 * time.Minute
	}
	if o.DiagTimeout == 0 {
		o.DiagTimeout = time.Minute
	}
	if o.ProviderTimeout == 0 {
		o.ProviderTimeout = 2 * time.Minute
	}
	return &Manager{o: o, runs: map[string]*run{}, pollers: map[string]*poller{}, events: make(chan struct{}, 1), poolRetry: map[string]time.Time{}, runtimes: map[string]runtimeState{}}, nil
}

// Run executes the control loop until ctx is cancelled or the mode is off and
// nothing is active. It returns nil in both cases.
func (m *Manager) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	m.mu.Lock()
	m.root = runCtx
	m.mu.Unlock()
	mode, err := m.o.Files.ReadMode()
	m.mu.Lock()
	m.previousMode = mode
	m.mu.Unlock()
	m.accepting.Store(err == nil && mode == control.ModeOn)
	if err := m.activateStartup(runCtx, mode); err != nil {
		return err
	}
	if err := m.Reconcile(runCtx); err != nil {
		return fmt.Errorf("reconcile: %w", err)
	}
	ticker := time.NewTicker(m.o.Tick)
	defer ticker.Stop()
	defer m.stopPollers()
	performance := perf.NewSampler(m.o.Files.Dir)
	nextPerformance := time.Now()
	for {
		mode, err := m.o.Files.ReadMode()
		if err != nil {
			m.o.Log.Error("read mode", "error", err)
			mode = control.ModeDrain
		}
		exit := m.apply(runCtx, mode)
		m.writeStatus(ctx, mode)
		if !time.Now().Before(nextPerformance) {
			if sample, err := performance.Sample(); err == nil {
				var disk perf.DiskSpace
				if sample.Disk != nil {
					disk = *sample.Disk
				}
				var commit perf.CommitSpace
				if sample.Commit != nil {
					commit = *sample.Commit
				}
				m.o.Log.Info("host performance", "cpu_percent", sample.CPUPercent, "cpu_interval_available", sample.CPUValid, "logical_cpu_percent", sample.CorePercent, "memory_used_bytes", sample.TotalBytes-sample.AvailableBytes, "memory_total_bytes", sample.TotalBytes, "memory_available_bytes", sample.AvailableBytes, "commit_sample_available", sample.Commit != nil, "commit_used_bytes", commit.UsedBytes, "commit_limit_bytes", commit.LimitBytes, "commit_headroom_bytes", commit.HeadroomBytes(), "commit_os_peak_since_boot_bytes", commit.PeakSinceBootBytes, "controller_disk_sample_available", sample.Disk != nil, "controller_disk_total_bytes", disk.TotalBytes, "controller_disk_available_bytes", disk.AvailableBytes)
			}
			nextPerformance = time.Now().Add(time.Minute)
			if m.o.Cache != nil {
				m.o.Cache.LogSummary()
			}
		}
		if exit {
			m.o.Log.Info("mode off and nothing active; daemon exiting")
			// Only parked teardowns remain; their records wait for the next
			// start. Join every lifecycle goroutine before returning.
			m.cancelRuns(false)
			cancel()
			m.wg.Wait()
			// A signal always leaves runtimes for adoption, including a signal
			// racing with the off-exit join.
			if ctx.Err() == nil {
				m.deactivate(ctx)
				m.setPhase("exiting")
				m.writeStatus(ctx, mode)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			m.o.Log.Info("shutting down; active guests keep running and are reconciled on the next start")
			m.stopPollers()
			m.cancelRuns(false)
			cancel()
			m.wg.Wait()
			return nil
		case <-m.o.Wake:
		case <-m.events:
		case <-ticker.C:
		}
	}
}

// apply moves the daemon toward the mode. It reports whether the daemon
// should exit.
func (m *Manager) apply(ctx context.Context, mode control.Mode) bool {
	// Keep the session open in drain and stop. Local execution capacity is
	// zero in those modes; assigned jobs wait for on. Only off closes it.
	m.observeMode(mode)
	m.accepting.Store(mode == control.ModeOn)
	switch mode {
	case control.ModeOn:
		starting := m.activateAsync(ctx, time.Now())
		phase := "polling"
		if m.o.Config.GitHub.Demand == config.DemandJIT {
			m.fillPool(ctx)
			phase = "maintaining idle pool"
		} else {
			m.startPollers(ctx)
		}
		if starting {
			phase = "starting host runtimes"
		}
		m.setPhase(phase)
	case control.ModeDrain:
		if m.o.Config.GitHub.Demand == config.DemandScaleSet {
			m.startPollers(ctx)
		}
		if m.activeCount() > 0 {
			m.setPhase("draining")
		} else {
			m.setPhase("idle")
		}
	case control.ModeStop:
		if m.o.Config.GitHub.Demand == config.DemandScaleSet {
			m.startPollers(ctx)
		}
		if m.activeCount() > 0 {
			m.setPhase("stopping")
			m.cancelRuns(true)
		} else {
			m.setPhase("idle")
		}
	case control.ModeOff:
		// Count only after the pollers have stopped: a poller can be inside
		// launch until stopPollers returns.
		m.stopPollers()
		if m.activeCount() > 0 {
			m.setPhase("draining")
		} else {
			m.setPhase("releasing host runtimes")
			return true
		}
	}
	return false
}

func (m *Manager) setPhase(p string) {
	m.mu.Lock()
	changed := m.phase != p
	m.phase = p
	m.mu.Unlock()
	if changed {
		m.o.Log.Info("phase", "phase", p)
	}
}

// Phase is the daemon's current phase, for tests and status.
func (m *Manager) Phase() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.phase
}

func (m *Manager) notify() {
	select {
	case m.events <- struct{}{}:
	default:
	}
}

// activeCount is the number of runs that drain, stop and off wait for.
// Parked teardowns are excluded: only an operator can resolve them.
func (m *Manager) activeCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.runs {
		if !r.parked.Load() {
			n++
		}
	}
	return n
}

func (m *Manager) activeFor(provider string) []*state.Instance {
	var out []*state.Instance
	for _, inst := range m.o.Store.List() {
		if inst.Provider == provider {
			out = append(out, inst)
		}
	}
	return out
}

// cancelRuns ends every active run. With immediate, runs abandon their job
// and tear down now; otherwise they just stop waiting (the daemon is
// exiting and will reconcile later).
func (m *Manager) cancelRuns(immediate bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.runs {
		if immediate {
			r.once.Do(func() { close(r.stopNow) })
		} else {
			r.cancel()
		}
	}
}

// capacity is how many more guests provider p may start right now, and how
// many running guests on the host are not ours. It is zero unless the mode
// is on.
func (m *Manager) capacity(ctx context.Context, name string) (int, int) {
	return m.capacityWith(ctx, name, nil)
}

// capacityWith is capacity using an inventory already listed this tick, or a
// fresh one when inv is nil.
func (m *Manager) capacityWith(ctx context.Context, name string, inv *inventory) (int, int) {
	c, foreign := m.rawCapacityWith(ctx, name, inv)
	if !m.accepting.Load() {
		return 0, foreign
	}
	return c, foreign
}

// listTimeout bounds one provider inventory on the control loop or a poller.
const listTimeout = 30 * time.Second

// inventory is one provider List result.
type inventory struct {
	owned   []provider.Owned
	foreign []provider.Foreign
	err     error
}

func (m *Manager) list(ctx context.Context, name string) inventory {
	lctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	owned, foreign, err := m.o.Providers[name].List(lctx)
	if err != nil {
		m.runtimeListFailed(name)
	}
	return inventory{owned: owned, foreign: foreign, err: err}
}

func (m *Manager) rawCapacity(ctx context.Context, name string) (int, int) {
	return m.rawCapacityWith(ctx, name, nil)
}

func (m *Manager) rawCapacityWith(ctx context.Context, name string, inv *inventory) (int, int) {
	if !m.runtimeActive(name) {
		return 0, 0
	}
	pcfg := m.o.Config.Providers[name]
	p := m.o.Providers[name]
	all := m.o.Store.List()
	activeTotal, activeHere, pending := 0, 0, 0
	var guests []*state.Instance
	for _, inst := range all {
		if inst.Phase == state.PhaseDeregistering {
			pending++
			continue
		}
		guests = append(guests, inst)
		activeTotal++
		if inst.Provider == name {
			activeHere++
		}
	}

	// Reserve record slots too: simultaneous guest losses cannot grow the
	// backlog beyond max_instances + max_pending_cleanup - 1.
	limits := []int{m.o.Config.Budget.MaxInstances - activeTotal, m.o.Config.Budget.MaxInstances + m.o.Config.Budget.MaxPendingCleanup - 1 - len(all)}
	if pending >= m.o.Config.Budget.MaxPendingCleanup {
		limits = append(limits, 0)
	}
	if pcfg.MaxInstances > 0 {
		limits = append(limits, pcfg.MaxInstances-activeHere)
	}
	foreign := 0
	if caps := p.Capabilities(); caps.HostLimit > 0 {
		if inv == nil {
			fresh := m.list(ctx, name)
			inv = &fresh
		}
		if inv.err != nil {
			m.o.Log.Warn("list guests", "provider", name, "error", inv.err)
			return 0, 0
		}
		hostLimit := caps.HostLimit
		reserved := 0
		ours := activeHere
		tracked := recordedNames(guests)
		if pcfg.VZ != nil {
			hostLimit = pcfg.VZ.HostVMLimit
			reserved = pcfg.VZ.ForeignSlots
			// Apple's limit is per host. Count records across vz providers,
			// plus running orphans, exempting Linux only with clone-manifest
			// proof. Exact provider ownership lists other providers as foreign;
			// their recorded guests are already counted here.
			ours = 0
			// Only these records are already counted. A native VM with a
			// record for a removed/unknown provider still counts via inventory.
			tracked = make(map[string]bool)
			for _, inst := range guests {
				if m.o.Config.Providers[inst.Provider].VZ != nil {
					tracked[inst.Name] = true
					if !hostLimitExempt(m.o.Providers[inst.Provider], inst.Name) {
						ours++
					}
				}
			}
			for _, o := range inv.owned {
				if o.Running && !tracked[o.Name] && !hostLimitExempt(p, o.Name) {
					ours++
				}
			}
		}
		for _, f := range inv.foreign {
			if f.Running && !f.HostLimitExempt && !tracked[f.Name] {
				foreign++
			}
		}
		limits = append(limits, hostLimit-max(foreign, reserved)-ours)
	}
	if cpu, mem := guestSize(pcfg); cpu > 0 || mem > 0 {
		usedCPU, usedMem := 0, 0
		for _, inst := range guests {
			c, g := guestSize(m.o.Config.Providers[inst.Provider])
			if inst.CPU > 0 || inst.MemoryGB > 0 {
				c, g = inst.CPU, inst.MemoryGB
			}
			usedCPU += c
			usedMem += g
		}
		if cpu > 0 && m.o.Host.CPUs > 0 {
			limits = append(limits, (m.o.Host.CPUs-m.o.Config.Budget.ReserveCPU-usedCPU)/cpu)
		}
		if mem > 0 && m.o.Host.MemoryBytes > 0 {
			hostGB := int(m.o.Host.MemoryBytes >> 30)
			limits = append(limits, (hostGB-m.o.Config.Budget.ReserveMemoryGB-usedMem)/mem)
		}
	}
	c := limits[0]
	for _, l := range limits[1:] {
		c = min(c, l)
	}
	return max(c, 0), foreign
}

// recordedNames are the guest names of active records. A provider reports a
// guest it cannot prove ours as foreign (Crosvm conservatively
// as running); its record already holds a slot, so capacity must not count it
// twice, and status lists it as a guest rather than as unmanaged.
func recordedNames(active []*state.Instance) map[string]bool {
	names := map[string]bool{}
	for _, inst := range active {
		names[inst.Name] = true
		if inst.EngineName != "" {
			names[inst.EngineName] = true
		}
	}
	return names
}

func guestSize(p config.Provider) (cpu, memGB int) {
	if p.HCS != nil {
		return p.HCS.CPU, p.HCS.MemoryGB
	}
	if p.Crosvm != nil {
		return p.Crosvm.CPU, p.Crosvm.MemoryGB
	}
	if p.VZ != nil {
		if e := p.VZ.Containers; e != nil {
			return p.VZ.CPU + e.CPU, p.VZ.MemoryGB + e.MemoryGB
		}
		return p.VZ.CPU, p.VZ.MemoryGB
	}
	return 0, 0
}

// launch creates a new instance and starts its lifecycle goroutine.
func (m *Manager) launch(ctx context.Context, providerName string, scaleSetID int, sweep bool) (*state.Instance, error) {
	m.admissionMu.Lock()
	defer m.admissionMu.Unlock()
	if !m.runtimeActive(providerName) {
		return nil, fmt.Errorf("no capacity for provider %s: host runtime is inactive", providerName)
	}
	if capacity, _ := m.capacity(ctx, providerName); capacity == 0 {
		return nil, fmt.Errorf("no capacity for provider %s", providerName)
	}
	id := m.o.NewID()
	inst := &state.Instance{
		ID:         id,
		Provider:   providerName,
		Name:       config.NamePrefix + providerName + "-" + id,
		ScaleSetID: scaleSetID,
		Phase:      state.PhaseCreating,
		CreatedAt:  time.Now(),
		Sweep:      sweep,
	}
	if m.o.Config.Providers[providerName].Crosvm != nil || m.o.Config.Providers[providerName].HCS != nil {
		inst.CPU, inst.MemoryGB = guestSize(m.o.Config.Providers[providerName])
	}
	if t := m.o.Config.Providers[providerName].VZ; t != nil && t.Containers != nil {
		inst.EngineName = inst.Name + "-engine"
		inst.ContainerEngine = t.Containers.Engine
		inst.CPU, inst.MemoryGB = guestSize(m.o.Config.Providers[providerName])
	}
	if err := m.o.Store.Put(inst); err != nil {
		return nil, err
	}
	m.mu.Lock()
	root := m.root
	m.mu.Unlock()
	if root == nil {
		root = ctx
	}
	m.track(root, inst, false)
	return inst, nil
}

// track starts the lifecycle goroutine for inst. adopted runs skip creation
// and resume at the runner wait.
func (m *Manager) track(ctx context.Context, inst *state.Instance, adopted bool) {
	rctx, cancel := context.WithCancel(ctx)
	r := &run{inst: inst, cancel: cancel, stopNow: make(chan struct{})}
	m.mu.Lock()
	m.runs[inst.ID] = r
	m.mu.Unlock()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer cancel()
		m.lifecycle(rctx, r, adopted)
		m.mu.Lock()
		delete(m.runs, inst.ID)
		m.mu.Unlock()
		m.notify()
	}()
}

// Wait blocks until every active run has finished, for tests.
func (m *Manager) Wait() { m.wg.Wait() }

func (m *Manager) fail(inst *state.Instance, err error) {
	if m.o.Config.GitHub.Demand == config.DemandJIT {
		m.mu.Lock()
		m.poolRetry[inst.Provider] = time.Now().Add(30 * time.Second)
		m.mu.Unlock()
	}
	msg := err.Error()
	m.o.Log.Error("instance failed", "instance", inst.ID, "name", inst.Name, "error", msg)
	_ = m.o.Store.RecordError(inst.ID, msg)
	_, _ = m.o.Store.Update(inst.ID, func(i *state.Instance) {
		i.Phase = state.PhaseFailed
		i.LastError = msg
	})
}

func (m *Manager) setPhaseOf(inst *state.Instance, p state.Phase, fn func(*state.Instance)) {
	_, _ = m.o.Store.Update(inst.ID, func(i *state.Instance) {
		i.Phase = p
		if fn != nil {
			fn(i)
		}
	})
	m.notify()
}

// lifecycle is the per-instance state machine. Every exit path tears the
// guest down and removes its state record, except daemon shutdown (the next
// start adopts the guest) and a parked teardown of a guest we do not own.
func (m *Manager) lifecycle(ctx context.Context, r *run, adopted bool) {
	inst := r.inst
	p := m.o.Providers[inst.Provider]
	pcfg := m.o.Config.Providers[inst.Provider]
	log := m.o.Log.With("instance", inst.ID, "name", inst.Name, "provider", inst.Provider)
	startupStage := func(stage string, started time.Time, err error) {
		log.Info("startup stage", "stage", stage, "duration_ms", time.Since(started).Milliseconds(), "success", err == nil)
	}
	var launchLog *os.File
	defer func() {
		if launchLog != nil {
			_ = launchLog.Close()
		}
	}()

	teardown := func(reason string) {
		delay := m.o.CleanupRetry
		for {
			out := m.teardown(context.WithoutCancel(ctx), inst, reason)
			if _, remains := m.o.Store.Get(inst.ID); !remains {
				return
			}
			if out == teardownUnowned {
				// Only an operator can resolve this. Back off, and let drain,
				// stop and off finish; the record stays for a later start.
				if !r.parked.Swap(true) {
					log.Warn("teardown parked: guest exists without our metadata; record kept for a later start")
					m.notify()
				}
			} else {
				if r.parked.Swap(false) {
					m.notify()
				}
				delay = m.o.CleanupRetry
			}
			if err := sleep(ctx, delay); err != nil {
				return
			}
			if out == teardownUnowned {
				delay = min(2*delay, max(m.o.UnownedRetryMax, m.o.CleanupRetry))
			}
		}
	}
	if adopted && (inst.Phase == state.PhaseDestroying || inst.Phase == state.PhaseDeregistering) {
		teardown("reconcile: unfinished teardown")
		return
	}

	if !adopted {
		spec, err := m.spec(inst, pcfg)
		if err != nil {
			m.fail(inst, err)
			teardown("bad spec")
			return
		}
		t0 := time.Now()
		if err := p.Create(ctx, spec); err != nil {
			m.fail(inst, fmt.Errorf("create: %w", err))
			teardown("create failed")
			return
		}
		cloneMS := time.Since(t0).Milliseconds()
		m.setPhaseOf(inst, state.PhaseBooting, func(i *state.Instance) {
			i.Timings.CloneMS = cloneMS
			i.LaunchArgs = spec.Launch.Args
		})
		if r.stopRequested() {
			teardown(reasonStopStartup)
			return
		}

		if m.o.LogDir != "" {
			f, err := os.OpenFile(filepath.Join(m.o.LogDir, inst.Name+".launch.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err == nil {
				launchLog = f
			}
		}
		var sink = os.Stderr
		if launchLog != nil {
			sink = launchLog
		}
		t1 := time.Now()
		if err := p.Start(ctx, inst.Name, sink); err != nil {
			m.fail(inst, fmt.Errorf("start: %w", err))
			teardown("start failed")
			return
		}
		// Stop must interrupt the boot and registration waits promptly. Only
		// waits use this context; mutations keep ctx so none is cut short.
		waitCtx, cancelWait := context.WithCancel(ctx)
		defer cancelWait()
		go func() {
			select {
			case <-r.stopNow:
				cancelWait()
			case <-waitCtx.Done():
			}
		}()
		readyCtx, cancelReady := context.WithTimeout(waitCtx, m.o.Config.Budget.ReadyTimeout.Duration)
		err = p.WaitReady(readyCtx, inst.Name)
		cancelReady()
		if err != nil {
			if r.stopRequested() {
				teardown(reasonStopStartup)
				return
			}
			m.fail(inst, fmt.Errorf("guest never became ready: %w", err))
			teardown("not ready")
			return
		}
		bootMS := time.Since(t1).Milliseconds()
		m.setPhaseOf(inst, state.PhaseReady, func(i *state.Instance) { i.Timings.BootMS = bootMS })
		log.Info("guest ready", "clone_ms", cloneMS, "boot_ms", bootMS)

		t2 := time.Now()
		if r.stopRequested() {
			teardown(reasonStopStartup)
			return
		}
		if m.o.Config.GitHub.Demand == config.DemandJIT && !m.accepting.Load() {
			teardown("idle pool paused")
			return
		}
		var jit github.JITConfig
		if m.o.Config.GitHub.Demand == config.DemandJIT {
			jit, err = m.o.JIT.GenerateRunnerJIT(ctx, inst.Name, m.o.Config.GitHub.RunnerGroup, pcfg.Labels, "_work")
		} else {
			jit, err = m.o.GitHub.GenerateJIT(ctx, inst.ScaleSetID, inst.Name, "_work")
		}
		startupStage("jit_generation", t2, err)
		if err != nil {
			m.fail(inst, fmt.Errorf("jit config: %w", err))
			teardown("jit failed")
			return
		}
		_, _ = m.o.Store.Update(inst.ID, func(i *state.Instance) { i.RunnerID = jit.RunnerID })
		inst.RunnerID = jit.RunnerID
		if r.stopRequested() {
			// The registration exists but no listener took it: teardown
			// deregisters the recorded runner ID.
			teardown(reasonStopStartup)
			return
		}
		if m.o.Config.GitHub.Demand == config.DemandJIT && !m.accepting.Load() {
			teardown("idle pool paused")
			return
		}
		if err := p.StartRunner(ctx, inst.Name, jit.Encoded); err != nil {
			m.fail(inst, fmt.Errorf("start runner: %w", err))
			teardown("runner start failed")
			return
		}
		listenStart := time.Now()
		err = m.waitListening(waitCtx, p, inst)
		startupStage("listener_wait", listenStart, err)
		if err != nil {
			if r.stopRequested() {
				// The listener may already hold a job: cancel it through the
				// official runner before the guest goes.
				teardown("stop requested")
				return
			}
			m.fail(inst, err)
			teardown("runner never listened")
			return
		}
		cancelWait()
		registerMS := time.Since(t2).Milliseconds()
		m.setPhaseOf(inst, state.PhaseListening, func(i *state.Instance) {
			i.ListenedAt = time.Now()
			i.Timings.RegisterMS = registerMS
		})
		log.Info("runner listening", "register_ms", registerMS)
	} else {
		log.Info("adopted running guest")
	}

	reason := m.waitRunner(ctx, r, p, inst)
	if reason == reasonCancelled {
		// The daemon is exiting, not the job: the guest keeps running and the
		// next start adopts or cleans it up.
		log.Info("leaving guest running for the next start")
		return
	}
	teardown(reason)
}

const (
	reasonCancelled   = "daemon shutting down"
	reasonStopStartup = "stop requested during startup"
)

func (m *Manager) spec(inst *state.Instance, pcfg config.Provider) (provider.Spec, error) {
	spec := provider.Spec{
		Name: inst.Name,
		Meta: provider.Metadata{ControllerID: m.o.Store.ControllerID(), InstanceID: inst.ID, CreatedAt: inst.CreatedAt.UTC().Format(time.RFC3339)},
	}
	switch pcfg.Type {
	case "hcs":
		spec.Baseline = pcfg.HCS.Image
		spec.CPU = pcfg.HCS.CPU
		spec.MemoryMB = pcfg.HCS.MemoryGB * 1024
		if inst.CPU > 0 && inst.MemoryGB > 0 {
			spec.CPU = inst.CPU
			spec.MemoryMB = inst.MemoryGB * 1024
		}
	case "crosvm":
		spec.Baseline = pcfg.Crosvm.BaselineName
		spec.CPU = pcfg.Crosvm.CPU
		spec.MemoryMB = pcfg.Crosvm.MemoryGB * 1024
		if inst.CPU > 0 && inst.MemoryGB > 0 {
			spec.CPU = inst.CPU
			spec.MemoryMB = inst.MemoryGB * 1024
		}
	case "vz":
		spec.Baseline = pcfg.VZ.Baseline
		spec.CPU = pcfg.VZ.CPU
		spec.MemoryMB = pcfg.VZ.MemoryGB * 1024
	default:
		return spec, fmt.Errorf("unsupported provider type %q", pcfg.Type)
	}
	return spec, nil
}

// waitListening polls until the runner reports a session with GitHub.
func (m *Manager) waitListening(ctx context.Context, p provider.Provider, inst *state.Instance) error {
	deadline := time.Now().Add(m.o.Config.Budget.ReadyTimeout.Duration)
	probe := runnerProbe{}
	for {
		if !time.Now().Before(deadline) {
			return errors.New("runner did not connect to GitHub in time")
		}
		st, delay, err := m.probeRunner(ctx, p, inst, deadline, &probe)
		if err != nil {
			return fmt.Errorf("runner status: %w", err)
		}
		if delay != 0 {
			if err := sleep(ctx, min(delay, time.Until(deadline))); err != nil {
				return err
			}
			continue
		}
		m.observeJob(inst, st.Job)
		switch st.State {
		case provider.RunnerListening, provider.RunnerRunning:
			return nil
		case provider.RunnerExited:
			return fmt.Errorf("runner exited with code %d before listening", st.ExitCode)
		}
		if time.Now().After(deadline) {
			return errors.New("runner did not connect to GitHub in time")
		}
		if err := sleep(ctx, m.o.PollInterval); err != nil {
			return err
		}
	}
}

// waitRunner watches the runner until it exits or a budget says to stop.
func (m *Manager) waitRunner(ctx context.Context, r *run, p provider.Provider, inst *state.Instance) string {
	probe := runnerProbe{}
	for {
		select {
		case <-r.stopNow:
			return "stop requested"
		case <-ctx.Done():
			return reasonCancelled
		default:
		}
		cur, ok := m.o.Store.Get(inst.ID)
		if !ok {
			return "record removed"
		}
		deadline := cur.CreatedAt.Add(m.o.Config.Budget.JobTimeout.Duration)
		if !time.Now().Before(deadline) {
			return "job timeout"
		}
		st, delay, err := m.probeRunner(ctx, p, inst, deadline, &probe)
		select {
		case <-r.stopNow:
			return "stop requested"
		case <-ctx.Done():
			return reasonCancelled
		default:
		}
		if !time.Now().Before(deadline) {
			return "job timeout"
		}
		if err != nil {
			return "runner unreachable: " + err.Error()
		}
		if delay != 0 {
			select {
			case <-r.stopNow:
				return "stop requested"
			case <-ctx.Done():
				return reasonCancelled
			case <-time.After(min(delay, time.Until(deadline))):
			}
			continue
		}
		m.observeJob(inst, st.Job)
		switch st.State {
		case provider.RunnerExited:
			m.setPhaseOf(inst, state.PhaseFinished, nil)
			return fmt.Sprintf("runner exited %d", st.ExitCode)
		case provider.RunnerAbsent:
			if cur.Phase == state.PhaseListening || cur.Phase == state.PhaseRunning {
				return "runner process vanished"
			}
		case provider.RunnerRunning:
			if cur.Phase != state.PhaseRunning {
				m.setPhaseOf(inst, state.PhaseRunning, nil)
			}
		case provider.RunnerListening:
			if cur.Phase == state.PhaseReady || cur.Phase == state.PhaseBooting {
				m.setPhaseOf(inst, state.PhaseListening, func(i *state.Instance) {
					if i.ListenedAt.IsZero() {
						i.ListenedAt = time.Now()
					}
				})
			}
			if m.o.Config.GitHub.Demand == config.DemandJIT && !m.accepting.Load() && cur.Job == nil && st.Job == nil {
				// Withdraw before stopping the guest. A busy-runner rejection
				// protects a job accepted concurrently with drain/off.
				if err := m.registry().RemoveRunner(ctx, cur.RunnerID); err == nil {
					return "idle pool paused"
				}
			}
			if cur.Phase == state.PhaseRunning && cur.Job == nil {
				m.setPhaseOf(inst, state.PhaseListening, nil)
			}
		}
		if time.Since(cur.CreatedAt) > m.o.Config.Budget.JobTimeout.Duration {
			return "job timeout"
		}
		idle := m.o.Config.Budget.IdleTimeout.Duration
		if cur.Sweep {
			idle = m.o.Config.Budget.SweepIdleTimeout.Duration
		}
		if cur.Job == nil && st.State == provider.RunnerListening && st.Job == nil && cur.Phase == state.PhaseListening && !cur.ListenedAt.IsZero() && time.Since(cur.ListenedAt) > idle {
			if m.o.Config.GitHub.Demand == config.DemandJIT {
				if err := m.registry().RemoveRunner(ctx, cur.RunnerID); err != nil {
					if err := sleep(ctx, m.o.PollInterval); err != nil {
						return reasonCancelled
					}
					continue
				}
			}
			if cur.Sweep {
				return "sweep found no queued job"
			}
			return "idle timeout"
		}
		select {
		case <-r.stopNow:
			return "stop requested"
		case <-ctx.Done():
			return reasonCancelled
		case <-time.After(m.o.PollInterval):
		}
	}
}

// operationTimeout bounds one Status, Stop (after its grace) or Delete call.
func (m *Manager) operationTimeout(p provider.Provider) time.Duration {
	return max(m.o.ProviderTimeout, p.Capabilities().OperationTimeout)
}

// teardownOutcome tells the lifecycle how to retry a retained record.
type teardownOutcome int

const (
	teardownDone    teardownOutcome = iota // record removed
	teardownRetry                          // transient failure; retry soon
	teardownUnowned                        // guest exists without our metadata; operator needed
)

// teardown collects diagnostics, stops and deletes the guest, deregisters
// the runner, and removes the state record. It never touches anything whose
// ownership the provider cannot prove. ctx is independent of daemon shutdown;
// every provider and GitHub call gets its own deadline, so a guest-controlled
// diagnostics stream or a hung engine cannot hold the capacity slot forever.
func (m *Manager) teardown(ctx context.Context, inst *state.Instance, reason string) teardownOutcome {
	p := m.o.Providers[inst.Provider]
	log := m.o.Log.With("instance", inst.ID, "name", inst.Name)
	log.Info("tearing down", "reason", reason)
	t0 := time.Now()
	cur, _ := m.o.Store.Get(inst.ID)
	if cur == nil {
		cur = inst
	}
	call := func(d time.Duration, fn func(context.Context) error) error { return bounded(ctx, d, fn) }
	status := func() (provider.Status, error) {
		var st provider.Status
		err := call(m.operationTimeout(p), func(c context.Context) error {
			var err error
			st, err = p.Status(c, inst.Name)
			return err
		})
		return st, err
	}

	if cur.Phase != state.PhaseDeregistering {
		st, err := status()
		// vz reports a guest without our metadata as Exists && !Owned;
		// HCS and Crosvm return ErrNotOwned. Both wait for an operator.
		if errors.Is(err, provider.ErrNotOwned) || err == nil && st.Exists && !st.Owned {
			log.Error("guest exists without provable ownership; refusing to touch it", "error", err)
			_ = m.o.Store.RecordError(inst.ID, "guest "+inst.Name+" is not owned; left untouched")
			return teardownUnowned
		}
		if err != nil {
			log.Warn("status before teardown; retaining guest reservation", "error", err)
			return teardownRetry
		}
		if st.Exists {
			if st.Running && (reason == "stop requested" || reason == "job timeout" || reason == "reconcile: unfinished teardown") {
				// The official worker can spend 7.5 s on SIGINT and another
				// 2.5 s on SIGTERM before killing a stubborn step. Leave time
				// afterwards for it to report the result to GitHub.
				if err := call(30*time.Second, func(c context.Context) error { return p.StopRunner(c, inst.Name) }); err != nil {
					log.Warn("stop runner; forcing guest teardown", "error", err)
				}
			}
			if st.Running && m.o.DiagDir != "" {
				m.setPhaseOf(inst, state.PhaseCollecting, nil)
				dir := filepath.Join(m.o.DiagDir, time.Now().UTC().Format("20060102T150405Z")+"-"+inst.Name)
				if err := call(m.o.DiagTimeout, func(c context.Context) error { return diag.Collect(c, p, inst.Name, dir, cur, reason) }); err != nil {
					log.Warn("collect diagnostics", "error", err)
				} else {
					_, _ = m.o.Store.Update(inst.ID, func(i *state.Instance) { i.DiagDir = dir })
				}
			}
			m.setPhaseOf(inst, state.PhaseDestroying, nil)
			if st.Running {
				const grace = 30 * time.Second
				if err := call(grace+m.operationTimeout(p), func(c context.Context) error { return p.Stop(c, inst.Name, grace) }); err != nil {
					log.Warn("stop guest", "error", err)
				}
			}
			if err := call(m.operationTimeout(p), func(c context.Context) error { return p.Delete(c, inst.Name) }); err != nil && !errors.Is(err, provider.ErrNotFound) {
				log.Error("delete guest; record kept for the next reconcile", "error", err)
				_ = m.o.Store.RecordError(inst.ID, "delete: "+err.Error())
				return teardownRetry
			}
		}
		// Only confirmed absence releases host resources. Persist the proof before
		// trying GitHub, so a busy registration never blocks a replacement VM.
		if st, err := status(); err != nil || st.Exists {
			log.Warn("guest deletion not confirmed; retaining reservation", "exists", st.Exists, "error", err)
			return teardownRetry
		}
		updated, err := m.o.Store.Update(inst.ID, func(i *state.Instance) {
			i.Phase = state.PhaseDeregistering
			i.GuestDeletedAt = time.Now()
			i.Timings.TeardownMS = time.Since(t0).Milliseconds()
		})
		if err != nil {
			log.Error("persist guest deletion", "error", err)
			return teardownRetry
		}
		cur = updated
		log.Info("guest deleted; host capacity released", "teardown_ms", cur.Timings.TeardownMS)
		m.notify()
	}
	if cur.RunnerID == 0 {
		// A timed-out registration request may still have created a runner.
		var id int64
		err := call(m.o.ProviderTimeout, func(c context.Context) error {
			var err error
			id, err = m.registry().RunnerByName(c, inst.Name)
			return err
		})
		if err != nil {
			_, _ = m.o.Store.Update(inst.ID, func(i *state.Instance) { i.CleanupPending = true })
			_ = m.o.Store.RecordError(inst.ID, "look up runner: "+err.Error())
			return teardownRetry
		}
		cur.RunnerID = id
		_, _ = m.o.Store.Update(inst.ID, func(i *state.Instance) { i.RunnerID = id })
	}
	if cur.RunnerID != 0 {
		if err := call(m.o.ProviderTimeout, func(c context.Context) error { return m.registry().RemoveRunner(c, cur.RunnerID) }); err != nil {
			log.Warn("deregister runner; cleanup will retry", "runner_id", cur.RunnerID, "error", err)
			_, _ = m.o.Store.Update(inst.ID, func(i *state.Instance) { i.CleanupPending = true })
			_ = m.o.Store.RecordError(inst.ID, "deregister runner: "+err.Error())
			return teardownRetry
		}
	}
	teardownMS := cur.Timings.TeardownMS
	log.Info("guest gone", "teardown_ms", teardownMS, "deregistration_ms", time.Since(cur.GuestDeletedAt).Milliseconds(), "clone_ms", cur.Timings.CloneMS, "boot_ms", cur.Timings.BootMS, "register_ms", cur.Timings.RegisterMS, "job", jobLabel(cur.Job))
	if err := m.o.Store.Remove(inst.ID); err != nil {
		log.Error("remove record", "error", err)
		return teardownRetry
	}
	return teardownDone
}

func jobLabel(j *state.Job) string {
	if j == nil {
		return ""
	}
	label := fmt.Sprintf("%s/%s %s", j.Owner, j.Repository, j.DisplayName)
	if j.RunID != 0 {
		label += fmt.Sprintf(" (run %d)", j.RunID)
	}
	return label
}

// ErrRefused marks a configuration that conflicts with retained records.
// Restarting cannot fix it; the operator must restore the old configuration
// or finish cleanup with it.
var ErrRefused = errors.New("configuration refused")

// Reconcile aligns state, the engines, and GitHub after a start. Owned
// guests with a live runner are adopted; everything else of ours is torn
// down; nothing without our metadata is touched.
func (m *Manager) Reconcile(ctx context.Context) error {
	records := m.o.Store.List()
	for _, inst := range records {
		pc := m.o.Config.Providers[inst.Provider]
		if pc.VZ != nil && ((pc.VZ.Containers != nil) != (inst.EngineName != "")) {
			return fmt.Errorf("%w: cannot change container topology with retained records; finish cleanup first", ErrRefused)
		}
		if pc.VZ != nil && pc.VZ.Containers != nil && inst.ContainerEngine != pc.VZ.Containers.Engine {
			return fmt.Errorf("%w: cannot change container engine with retained records; finish cleanup first", ErrRefused)
		}
		if (inst.ScaleSetID == 0) != (m.o.Config.GitHub.Demand == config.DemandJIT) {
			return fmt.Errorf("%w: cannot change demand mode with retained instance records; finish cleanup first", ErrRefused)
		}
	}
	byName := map[string]*state.Instance{}
	var resume []*state.Instance
	for _, inst := range records {
		byName[inst.Name] = inst
	}
	for _, inst := range records {
		p := m.o.Providers[inst.Provider]
		if p == nil {
			m.o.Log.Error("record for unknown provider; left in place", "instance", inst.ID, "provider", inst.Provider)
			continue
		}
		if inst.Phase == state.PhaseDeregistering {
			resume = append(resume, inst)
			continue
		}
		if validator, ok := p.(interface{ ValidateRetained(string) error }); ok {
			if err := validator.ValidateRetained(inst.Name); err != nil {
				// Keep the record in byName to prevent orphan cleanup. Do not
				// track it: adoption and teardown both require its original contract.
				m.o.Log.Error("retained guest validation; record kept untouched", "instance", inst.ID, "provider", inst.Provider, "error", err)
				msg := "retained guest validation: " + err.Error()
				_ = m.o.Store.RecordError(inst.ID, msg)
				_, _ = m.o.Store.Update(inst.ID, func(i *state.Instance) { i.LastError = msg })
				continue
			}
		}
		var st provider.Status
		err := bounded(ctx, m.operationTimeout(p), func(c context.Context) error {
			var err error
			st, err = p.Status(c, inst.Name)
			return err
		})
		if err != nil {
			// Unprovable (not owned, corrupt, or unreachable): keep the record
			// and its reservation, touch nothing, and reconcile the rest. The
			// next start tries again.
			m.o.Log.Error("reconcile status; record kept untouched", "instance", inst.ID, "name", inst.Name, "error", err)
			msg := "reconcile status: " + err.Error()
			_ = m.o.Store.RecordError(inst.ID, msg)
			_, _ = m.o.Store.Update(inst.ID, func(i *state.Instance) { i.LastError = msg })
			continue
		}
		if inst.Phase != state.PhaseDestroying && st.Exists && st.Owned && st.Running {
			var rs provider.RunnerStatus
			err := bounded(ctx, m.o.RunnerStatusTimeout, func(c context.Context) error {
				var err error
				rs, err = p.RunnerStatus(c, inst.Name)
				return err
			})
			if err == nil && (rs.State == provider.RunnerRunning || rs.State == provider.RunnerListening) {
				m.o.Log.Info("adopting running guest", "instance", inst.ID, "name", inst.Name, "phase", inst.Phase)
				resume = append(resume, inst)
				continue
			}
		}
		m.setPhaseOf(inst, state.PhaseDestroying, nil)
		inst.Phase = state.PhaseDestroying
		resume = append(resume, inst)
	}
	for name, p := range m.o.Providers {
		inv := m.list(ctx, name)
		if inv.err != nil {
			if !m.runtimeActive(name) && !m.needsRuntime(name) {
				m.o.Log.Warn("inactive host runtime unavailable; skipping inventory", "provider", name, "error", inv.err)
				continue
			}
			return fmt.Errorf("list %s: %w", name, inv.err)
		}
		for _, o := range inv.owned {
			if _, known := byName[o.Name]; known {
				continue
			}
			m.o.Log.Warn("orphaned guest with our metadata; deleting", "provider", name, "name", o.Name)
			if o.Running {
				const grace = 30 * time.Second
				_ = bounded(ctx, grace+m.operationTimeout(p), func(c context.Context) error { return p.Stop(c, o.Name, grace) })
			}
			if err := bounded(ctx, m.operationTimeout(p), func(c context.Context) error { return p.Delete(c, o.Name) }); err != nil {
				m.o.Log.Error("delete orphan", "name", o.Name, "error", err)
			}
			var id int64
			err := bounded(ctx, m.o.ProviderTimeout, func(c context.Context) error {
				var err error
				id, err = m.registry().RunnerByName(c, o.Name)
				return err
			})
			if err == nil && id != 0 {
				if err := bounded(ctx, m.o.ProviderTimeout, func(c context.Context) error { return m.registry().RemoveRunner(c, id) }); err != nil {
					m.o.Log.Error("deregister orphan runner", "name", o.Name, "error", err)
				}
			}
		}
	}
	// Inventory first: teardown goroutines can remove native journals. Starting
	// them before List lets reconciliation race its own recovery and fail startup.
	for _, inst := range resume {
		m.track(ctx, inst, true)
	}
	return nil
}

// bounded runs fn with its own deadline, like each teardown call.
func bounded(ctx context.Context, d time.Duration, fn func(context.Context) error) error {
	cctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return fn(cctx)
}

// writeStatus publishes the snapshot the CLI reads.
func (m *Manager) writeStatus(ctx context.Context, mode control.Mode) {
	s := &control.Status{PID: os.Getpid(), Mode: mode, Phase: m.Phase(), Budgets: control.Budgets{MaxInstances: m.o.Config.Budget.MaxInstances, MaxPendingCleanup: m.o.Config.Budget.MaxPendingCleanup, Capacity: map[string]int{}}}
	now := time.Now()
	var active []*state.Instance
	for _, inst := range m.o.Store.List() {
		if inst.Phase != state.PhaseDeregistering {
			active = append(active, inst)
		}
		g := control.Guest{Instance: inst.Name, Provider: inst.Provider, Phase: inst.Phase, Job: jobLabel(inst.Job), Age: now.Sub(inst.CreatedAt).Round(time.Second).String()}
		if inst.Phase == state.PhaseDeregistering {
			s.PendingCleanup = append(s.PendingCleanup, g)
		} else {
			s.Guests = append(s.Guests, g)
		}
	}
	s.Budgets.Active = len(s.Guests)
	tracked := recordedNames(active)
	names := m.o.Config.ProviderNames()
	for _, name := range names {
		// One bounded inventory per provider per tick serves both capacity
		// and the unmanaged report.
		var inv inventory
		if m.runtimeActive(name) {
			inv = m.list(ctx, name)
		}
		c, foreign := m.capacityWith(ctx, name, &inv)
		s.Budgets.Capacity[name] = c
		s.Budgets.Foreign += foreign
		if inv.err == nil {
			for _, f := range inv.foreign {
				if f.Prefixed && !tracked[f.Name] {
					s.Unmanaged = append(s.Unmanaged, name+": "+f.Name)
				}
			}
		}
	}
	sort.Strings(s.Unmanaged)
	errs := m.o.Store.Errors()
	if len(errs) > 5 {
		errs = errs[len(errs)-5:]
	}
	s.LastErrors = errs
	m.mu.Lock()
	for _, name := range names {
		if e := m.runtimes[name].lastError; e.Message != "" {
			s.LastErrors = append(s.LastErrors, e)
		}
	}
	m.mu.Unlock()
	if err := m.o.Files.WriteStatus(s); err != nil {
		m.o.Log.Warn("write status", "error", err)
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Describe formats a status snapshot for humans.
func Describe(s *control.Status, mode control.Mode, alive bool) string {
	var b strings.Builder
	if s == nil {
		fmt.Fprintf(&b, "mode: %s\ndaemon: not running (no status yet)\n", mode)
		return b.String()
	}
	daemon := "running"
	if !alive {
		daemon = "not running (last snapshot " + s.UpdatedAt.Format(time.RFC3339) + ")"
	}
	fmt.Fprintf(&b, "mode: %s\ndaemon: %s\nphase: %s\n", mode, daemon, s.Phase)
	fmt.Fprintf(&b, "guests: %d active of %d max", s.Budgets.Active, s.Budgets.MaxInstances)
	if s.Budgets.Foreign > 0 {
		fmt.Fprintf(&b, ", %d foreign running", s.Budgets.Foreign)
	}
	b.WriteString("\n")
	for _, g := range s.Guests {
		fmt.Fprintf(&b, "  %s  %-11s  age %s", g.Instance, g.Phase, g.Age)
		if g.Job != "" {
			fmt.Fprintf(&b, "  job %s", g.Job)
		}
		b.WriteString("\n")
	}
	if len(s.PendingCleanup) > 0 {
		fmt.Fprintf(&b, "pending runner cleanup: %d (new provisioning pauses at %d)\n", len(s.PendingCleanup), s.Budgets.MaxPendingCleanup)
		for _, g := range s.PendingCleanup {
			fmt.Fprintf(&b, "  %s  VM deleted  age %s  job %s\n", g.Instance, g.Age, g.Job)
		}
	}
	names := make([]string, 0, len(s.Budgets.Capacity))
	for n := range s.Budgets.Capacity {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "capacity %s: %d more\n", n, s.Budgets.Capacity[n])
	}
	for _, u := range s.Unmanaged {
		fmt.Fprintf(&b, "unmanaged prefixed guest (never touched): %s\n", u)
	}
	for _, e := range s.LastErrors {
		fmt.Fprintf(&b, "error %s %s: %s\n", e.At.Format(time.RFC3339), e.Instance, e.Message)
	}
	return b.String()
}

func (m *Manager) registry() github.RunnerRegistry {
	if m.o.Config.GitHub.Demand == config.DemandJIT {
		return m.o.JIT
	}
	return m.o.GitHub
}

func (m *Manager) fillPool(ctx context.Context) {
	for _, name := range m.o.Config.ProviderNames() {
		m.mu.Lock()
		retry := m.poolRetry[name]
		m.mu.Unlock()
		if time.Now().Before(retry) {
			continue
		}
		idle := 0
		for _, inst := range m.activeFor(name) {
			switch inst.Phase {
			case state.PhaseCreating, state.PhaseBooting, state.PhaseReady, state.PhaseListening:
				idle++
			}
		}
		capacity, _ := m.capacity(ctx, name)
		needed := min(m.o.Config.Providers[name].IdlePool-idle, capacity)
		for range needed {
			if _, err := m.launch(ctx, name, 0, false); err != nil {
				m.o.Log.Error("launch idle pool", "provider", name, "error", err)
				break
			}
		}
	}
}

func (m *Manager) observeJob(inst *state.Instance, job *provider.RunnerJob) {
	if job == nil {
		return
	}
	cur, ok := m.o.Store.Get(inst.ID)
	if !ok || cur.Job != nil {
		return
	}
	owner, repo, ok := strings.Cut(job.Repository, "/")
	if !ok || owner == "" || repo == "" || job.RunID <= 0 {
		return
	}
	_, _ = m.o.Store.Update(inst.ID, func(i *state.Instance) {
		i.Job = &state.Job{Owner: owner, Repository: repo, RunID: job.RunID, DisplayName: job.Name, StartedAt: time.Now()}
	})
	m.o.Log.Info("runner job started", "instance", inst.ID, "run_id", job.RunID, "repository", job.Repository, "job", job.Name)
	m.notify()
}

// A configured Linux provider alone is insufficient: the clone must prove it.
func hostLimitExempt(p provider.Provider, name string) bool {
	proof, ok := p.(interface{ HostLimitExempt(string) bool })
	return ok && proof.HostLimitExempt(name)
}
