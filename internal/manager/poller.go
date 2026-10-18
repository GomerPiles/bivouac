package manager

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/state"
)

// pollBound caps one long poll; GitHub answers within about 50 s.
const pollBound = 65 * time.Second

// poller long-polls one provider's scale set in every mode but off.
type poller struct {
	name   string
	cancel context.CancelFunc
	done   chan struct{}

	// sweep checks for unassigned work after a session opens and when a
	// runner starts a run the scale set did not assign. It cannot recover
	// every job stranded by a previously advertised zero capacity.
	// Retained registration cleanup also gets one recovery sweep.
	sweep bool
	// assigned are run IDs the scale set assigned to us and not yet started.
	assigned     map[int64]bool
	cleanupSwept map[string]bool
}

func (m *Manager) startPollers(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, name := range m.o.Config.ProviderNames() {
		if _, running := m.pollers[name]; running {
			continue
		}
		pctx, cancel := context.WithCancel(ctx)
		p := &poller{name: name, cancel: cancel, done: make(chan struct{}), assigned: map[int64]bool{}}
		m.pollers[name] = p
		go m.poll(pctx, p)
	}
}

func (m *Manager) stopPollers() {
	m.mu.Lock()
	ps := make([]*poller, 0, len(m.pollers))
	for name, p := range m.pollers {
		ps = append(ps, p)
		delete(m.pollers, name)
	}
	m.mu.Unlock()
	for _, p := range ps {
		p.cancel()
		<-p.done
	}
}

// Polling reports whether any demand poller is running.
func (m *Manager) Polling() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pollers) > 0
}

func (m *Manager) poll(ctx context.Context, p *poller) {
	defer close(p.done)
	log := m.o.Log.With("provider", p.name)
	scaleSet := m.o.Config.Providers[p.name].ScaleSet
	backoff := time.Second
	for ctx.Err() == nil {
		healthy, err := m.pollSession(ctx, p, scaleSet)
		if ctx.Err() != nil {
			return
		}
		var wait time.Duration
		wait, backoff = reconnectDelay(backoff, healthy)
		log.Warn("scale set session ended; reconnecting", "error", err, "backoff", wait)
		if err := sleep(ctx, wait); err != nil {
			return
		}
	}
}

// reconnectDelay returns the wait before the next session and the backoff
// after it. A session that polled successfully starts over at one second;
// consecutive failures double up to a minute.
func reconnectDelay(backoff time.Duration, healthy bool) (wait, next time.Duration) {
	if healthy {
		backoff = time.Second
	}
	return backoff, min(2*backoff, time.Minute)
}

// pollSession runs one message session. healthy reports whether at least
// one poll succeeded, which resets the reconnect backoff.
func (m *Manager) pollSession(ctx context.Context, p *poller, scaleSet string) (healthy bool, err error) {
	log := m.o.Log.With("provider", p.name, "scaleset", scaleSet)
	labels := m.o.Config.Providers[p.name].ScaleSetLabelNames()
	ss, err := m.o.GitHub.Ensure(ctx, scaleSet, m.o.Config.GitHub.RunnerGroup, labels)
	if err != nil {
		return false, err
	}
	id := ss.ID
	if missing, extra := github.LabelDiff(labels, ss.Labels); len(missing)+len(extra) > 0 {
		log.Warn("scale set labels differ from config; GitHub fixes them at creation", "missing", missing, "extra", extra, "labels", ss.Labels)
	}
	owner := "bivouac-" + m.o.Store.ControllerID()
	if len(owner) > 64 {
		owner = owner[:64]
	}
	sess, err := m.o.GitHub.Open(ctx, id, owner)
	if err != nil {
		return false, err
	}
	defer func() { _ = sess.Close(context.WithoutCancel(ctx)) }()
	log.Info("polling scale set", "id", id)
	p.sweep = !m.o.NoSweep

	var lastStats *github.Statistics
	if st := sess.Statistics(); st != nil {
		lastStats = st
		log.Info("session statistics", "available", st.TotalAvailableJobs, "acquired", st.TotalAcquiredJobs, "assigned", st.TotalAssignedJobs, "running", st.TotalRunningJobs, "registered_runners", st.TotalRegisteredRunners, "idle_runners", st.TotalIdleRunners)
		m.converge(ctx, sess, p, id, st, nil)
	}
	lastID := 0
	for {
		capacity := m.pollCapacity(ctx, p.name)
		// GitHub's long poll returns within ~50 s. Bound every poll so a
		// request that the service holds longer (observed with zero
		// capacity) is retried with fresh capacity instead of hanging.
		pollCtx, cancelPoll := context.WithTimeout(ctx, pollBound)
		started := time.Now()
		log.Info("scale set poll", "capacity", capacity, "last_message_id", lastID)
		msg, err := sess.Poll(pollCtx, lastID, capacity)
		cancelPoll()
		result := "empty"
		if err != nil {
			result = "error"
		} else if msg != nil {
			result = "message"
		}
		log.Info("scale set poll result", "capacity", capacity, "result", result, "elapsed_ms", time.Since(started).Milliseconds())
		if err != nil {
			if ctx.Err() != nil {
				return healthy, err
			}
			if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "deadline exceeded") {
				log.Info("poll timed out; polling again", "capacity", capacity)
				m.converge(ctx, sess, p, id, lastStats, nil)
				continue
			}
			return healthy, err
		}
		healthy = true
		if msg == nil {
			m.converge(ctx, sess, p, id, lastStats, nil)
			continue
		}
		if msg.Statistics != nil {
			lastStats = msg.Statistics
		}
		log.Info("scale set message", "id", msg.MessageID, "available", len(msg.JobAvailableMessages), "assigned", len(msg.JobAssignedMessages), "started", len(msg.JobStartedMessages), "completed", len(msg.JobCompletedMessages), "total_assigned", statsField(lastStats))
		m.handleJobMessages(p, msg)
		m.converge(ctx, sess, p, id, lastStats, msg)
		if err := sess.Ack(context.WithoutCancel(ctx), msg.MessageID); err != nil {
			return healthy, err
		}
		lastID = msg.MessageID
	}
}

// pollCapacity is the total runner ceiling, including existing runners, not
// the number of free slots. Keep the session eligible even when execution is
// paused: jobs queued against a zero-capacity poll were not assigned later on
// github.com. Local capacity still gates every launch in converge.
func (m *Manager) pollCapacity(ctx context.Context, name string) int {
	free, _ := m.rawCapacity(ctx, name)
	return max(1, free+len(m.activeFor(name)))
}

// handleJobMessages binds job identities to instances by runner name and
// notices label-matched jobs.
func (m *Manager) handleJobMessages(p *poller, msg *github.Message) {
	byName := map[string]*state.Instance{}
	for _, inst := range m.o.Store.List() {
		byName[inst.Name] = inst
	}
	for _, j := range msg.JobAssignedMessages {
		if j.WorkflowRunID != 0 {
			p.assigned[j.WorkflowRunID] = true
		}
	}
	for _, j := range msg.JobStartedMessages {
		inst, ok := byName[j.RunnerName]
		if !ok {
			continue
		}
		job := &state.Job{RequestID: j.RunnerRequestID, Owner: j.OwnerName, Repository: j.RepositoryName, WorkflowRef: j.JobWorkflowRef, DisplayName: j.JobDisplayName, RunID: j.WorkflowRunID, StartedAt: time.Now()}
		_, _ = m.o.Store.Update(inst.ID, func(i *state.Instance) {
			i.Job = job
			if i.Phase == state.PhaseListening {
				i.Phase = state.PhaseRunning
			}
		})
		m.o.Log.Info("job started", "instance", inst.ID, "name", inst.Name, "job", jobLabel(job), "sweep", inst.Sweep)
		if j.WorkflowRunID != 0 && p.assigned[j.WorkflowRunID] {
			delete(p.assigned, j.WorkflowRunID)
		} else if !m.o.NoSweep {
			// The runner took a job GitHub routed by label, so a job the
			// scale set assigned (or more label-routed ones) may be waiting.
			m.o.Log.Info("runner took a label-routed job; a sweep follows", "instance", inst.ID, "run", j.WorkflowRunID)
			p.sweep = true
		}
	}
	for _, j := range msg.JobCompletedMessages {
		inst, ok := byName[j.RunnerName]
		if !ok {
			continue
		}
		_, _ = m.o.Store.Update(inst.ID, func(i *state.Instance) {
			if i.Job == nil {
				i.Job = &state.Job{RequestID: j.RunnerRequestID, Owner: j.OwnerName, Repository: j.RepositoryName, DisplayName: j.JobDisplayName, RunID: j.WorkflowRunID}
			}
			i.Job.Result = j.Result
			i.Job.FinishedAt = time.Now()
		})
		m.o.Log.Info("job completed", "instance", inst.ID, "name", inst.Name, "result", j.Result)
	}
	m.notify()
}

// converge acquires available jobs, starts guests for assigned jobs within
// capacity, starts a pending sweep, and retires surplus idle runners.
func (m *Manager) converge(ctx context.Context, sess github.Session, p *poller, scaleSetID int, stats *github.Statistics, msg *github.Message) {
	log := m.o.Log.With("provider", p.name)
	if !m.o.NoSweep {
		if p.cleanupSwept == nil {
			p.cleanupSwept = map[string]bool{}
		}
		// A dead runner can keep a label-routed job queued without an
		// assignment message. Try one fresh sweep per pending cleanup.
		for _, inst := range m.activeFor(p.name) {
			if inst.Phase == state.PhaseDeregistering && inst.CleanupPending && !p.cleanupSwept[inst.ID] {
				p.cleanupSwept[inst.ID] = true
				p.sweep = true
				log.Info("guest cleanup pending; a recovery sweep follows", "instance", inst.ID)
			}
		}
		for id := range p.cleanupSwept {
			if _, exists := m.o.Store.Get(id); !exists {
				delete(p.cleanupSwept, id)
			}
		}
	}
	capacity, _ := m.capacity(ctx, p.name)
	if msg != nil && len(msg.JobAvailableMessages) > 0 && capacity > 0 {
		ids := make([]int64, 0, len(msg.JobAvailableMessages))
		for _, j := range msg.JobAvailableMessages {
			ids = append(ids, j.RunnerRequestID)
		}
		idle := 0
		for _, inst := range m.activeFor(p.name) {
			if inst.Phase == state.PhaseListening && inst.Job == nil {
				idle++
			}
		}
		if n := capacity + idle; len(ids) > n {
			ids = ids[:n]
		}
		got, err := sess.Acquire(ctx, ids)
		if err != nil {
			log.Warn("acquire jobs", "error", err)
		} else {
			log.Info("acquired jobs", "requested", len(ids), "acquired", len(got))
		}
	}
	if stats == nil {
		return
	}
	active := m.activeFor(p.name)
	have, pendingJobs := 0, 0
	for _, inst := range active {
		if inst.Phase != state.PhaseDeregistering {
			have++
		} else if inst.Job != nil && inst.Job.FinishedAt.IsZero() {
			pendingJobs++
		}
	}
	// Deleted guests only account for jobs GitHub still reports running;
	// a terminal job whose registration remains cannot hide new demand.
	have += min(pendingJobs, stats.TotalRunningJobs)
	want := stats.TotalAssignedJobs
	for have < want && capacity > 0 && !m.sweeping(p) {
		inst, err := m.launch(ctx, p.name, scaleSetID, false)
		if err != nil {
			log.Error("launch", "error", err)
			break
		}
		log.Info("launching guest for assigned job", "instance", inst.ID, "name", inst.Name, "assigned", want, "active", have)
		have++
		capacity--
	}
	if p.sweep && capacity > 0 {
		sweeping := false
		for _, inst := range active {
			if inst.Sweep && inst.Job == nil && inst.Phase != state.PhaseDeregistering {
				sweeping = true
			}
		}
		if !sweeping {
			inst, err := m.launch(ctx, p.name, scaleSetID, true)
			if err != nil {
				log.Error("launch sweep", "error", err)
			} else {
				log.Info("launching sweep runner for jobs routed by label", "instance", inst.ID, "name", inst.Name)
				p.sweep = false
			}
		}
	}
	// Retire idle non-sweep runners the scale set no longer has jobs for.
	waiting := stats.TotalAssignedJobs - stats.TotalRunningJobs
	var idle []*state.Instance
	for _, inst := range m.activeFor(p.name) {
		if !inst.Sweep && inst.Phase == state.PhaseListening && inst.Job == nil && time.Since(inst.ListenedAt) > m.o.SurplusGrace {
			idle = append(idle, inst)
		}
	}
	for i := 0; i < len(idle)-waiting; i++ {
		// Withdraw the registration before stopping the guest, as JIT mode
		// does. A busy-runner rejection means GitHub just gave it a job:
		// keep it, and the job runs normally.
		if idle[i].RunnerID == 0 {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, m.o.ProviderTimeout)
		err := m.o.GitHub.RemoveRunner(rctx, idle[i].RunnerID)
		cancel()
		if err != nil {
			log.Info("surplus idle runner not withdrawn; keeping it", "instance", idle[i].ID, "name", idle[i].Name, "error", err)
			continue
		}
		log.Info("retiring surplus idle runner", "instance", idle[i].ID, "name", idle[i].Name, "waiting_jobs", waiting)
		m.stopRun(idle[i].ID)
	}
}

// sweeping reports whether a sweep is pending or a sweep runner is still
// waiting for a job. Assigned jobs are not served until it ends.
func (m *Manager) sweeping(p *poller) bool {
	if p.sweep {
		return true
	}
	for _, inst := range m.activeFor(p.name) {
		if inst.Sweep && inst.Job == nil && inst.Phase != state.PhaseDeregistering {
			return true
		}
	}
	return false
}

// stopRun asks one run to tear down immediately.
func (m *Manager) stopRun(id string) {
	m.mu.Lock()
	r, ok := m.runs[id]
	m.mu.Unlock()
	if ok {
		r.once.Do(func() { close(r.stopNow) })
	}
}

func statsField(s *github.Statistics) int {
	if s == nil {
		return -1
	}
	return s.TotalAssignedJobs
}
