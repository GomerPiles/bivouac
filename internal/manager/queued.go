package manager

import (
	"context"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/state"
)

func (m *Manager) startQueuePoller(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.queueCancel != nil {
		return
	}
	ctx, m.queueCancel = context.WithCancel(ctx)
	done := make(chan struct{})
	m.queueDone = done
	go func() {
		defer close(done)
		queue := m.o.JIT.(github.JobQueue)
		for {
			poll, cancel := context.WithTimeout(ctx, 45*time.Second)
			jobs, err := queue.QueuedJobs(poll, m.o.Config.GitHub.QueueRepositories)
			cancel()
			if ctx.Err() != nil {
				return
			}
			counts := map[string]int{}
			if err == nil {
				counts = queuedCounts(jobs, m.o.Config)
			} else {
				m.o.Log.Warn("queue demand unavailable; no guests launched", "error", err)
				_ = m.o.Store.RecordError("", err.Error())
			}
			m.mu.Lock()
			m.queueCounts, m.queueUpdated = counts, time.Now()
			m.mu.Unlock()
			if err == nil && m.accepting.Load() {
				m.launchQueued(ctx, counts)
			}
			m.notify()
			if err := sleep(ctx, m.o.QueuePollInterval); err != nil {
				return
			}
		}
	}()
}

func (m *Manager) stopQueuePoller() {
	m.mu.Lock()
	cancel, done := m.queueCancel, m.queueDone
	m.queueCancel, m.queueDone = nil, nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
		m.mu.Lock()
		m.queueCounts, m.queueUpdated = nil, time.Time{}
		m.mu.Unlock()
	}
}

func (m *Manager) queueWaiting(provider string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.queueUpdated.IsZero() && time.Since(m.queueUpdated) < 2*m.o.QueuePollInterval && m.queueCounts[provider] > 0
}

// A snapshot is consumed once, immediately after its read. Provisioning and
// listening guests already cover demand; running jobs do not hide queued work.
func (m *Manager) launchQueued(ctx context.Context, counts map[string]int) {
	for _, name := range m.o.Config.ProviderNames() {
		m.mu.Lock()
		retry := m.poolRetry[name]
		m.mu.Unlock()
		if counts[name] == 0 || time.Now().Before(retry) {
			continue
		}
		idle := 0
		for _, inst := range m.activeFor(name) {
			if inst.Job != nil {
				continue
			}
			switch inst.Phase {
			case state.PhaseCreating, state.PhaseBooting, state.PhaseReady, state.PhaseListening:
				idle++
			}
		}
		capacity, _ := m.capacity(ctx, name)
		for range min(counts[name]-idle, capacity) {
			mode, err := m.o.Files.ReadMode()
			if ctx.Err() != nil || err != nil || mode != control.ModeOn || !m.accepting.Load() {
				return
			}
			if _, err := m.launch(ctx, name, 0, false); err != nil {
				m.o.Log.Warn("queued-demand launch deferred", "provider", name, "error", err)
				break
			}
		}
	}
}

func queuedCounts(jobs []github.QueuedJob, cfg *config.Config) map[string]int {
	counts, seen := map[string]int{}, map[int64]bool{}
	group := cfg.GitHub.RunnerGroup
	if group == "" {
		group = "default"
	}
	for _, job := range jobs {
		if job.ID <= 0 || seen[job.ID] || job.Status != "queued" || job.Runner != 0 || len(job.Labels) == 0 ||
			job.Group != "" && !strings.EqualFold(job.Group, group) {
			continue
		}
		seen[job.ID] = true
		for _, name := range cfg.ProviderNames() {
			available := map[string]bool{}
			for _, label := range cfg.Providers[name].Labels {
				available[strings.ToLower(label)] = true
			}
			matches := true
			for _, label := range job.Labels {
				if label == "" || !available[strings.ToLower(label)] {
					matches = false
					break
				}
			}
			if matches {
				counts[name]++
				break // One job cannot create guests on two overlapping providers.
			}
		}
	}
	return counts
}
