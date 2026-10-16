package github

import (
	"context"
	"fmt"
	"sync"

	"github.com/actions/scaleset"
)

// Fake is an in-memory scale set service for manager tests. Tests push
// messages; the fake records acquisitions, JIT configs, and removals.
type Fake struct {
	mu        sync.Mutex
	nextID    int64
	scaleSets map[string]int
	Runners   map[int64]string // registered runner id -> name
	Removed   []int64
	Acquired  []int64
	JITs      []string // runner names that received a JIT config
	queue     chan *Message
	stats     Statistics
	// FailJIT makes the next GenerateJIT fail.
	FailJIT     error
	removeError error
	busyRunners map[int64]error
	closed      bool
	queuedJobs  []QueuedJob
	queueError  error
}

// NewFake returns an empty fake.
func NewFake() *Fake {
	return &Fake{scaleSets: map[string]int{}, Runners: map[int64]string{}, busyRunners: map[int64]error{}, queue: make(chan *Message, 64)}
}

// Push queues a message for the next Poll. Statistics default to the fake's
// current counts when the message carries none.
func (f *Fake) Push(m *Message) {
	f.mu.Lock()
	if m.Statistics == nil {
		s := f.stats
		m.Statistics = &s
	} else {
		f.stats = *m.Statistics
	}
	f.mu.Unlock()
	f.queue <- m
}

// SetStatistics sets what idle polls report.
func (f *Fake) SetStatistics(s Statistics) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stats = s
}

// Ensure implements ScaleSets.
func (f *Fake) Ensure(_ context.Context, name, _ string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.scaleSets[name]; ok {
		return id, nil
	}
	id := len(f.scaleSets) + 100
	f.scaleSets[name] = id
	return id, nil
}

// Open implements ScaleSets.
func (f *Fake) Open(context.Context, int, string) (Session, error) {
	return &fakeSession{f: f}, nil
}

// GenerateJIT implements ScaleSets.
func (f *Fake) GenerateJIT(_ context.Context, _ int, runnerName, _ string) (JITConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailJIT != nil {
		err := f.FailJIT
		f.FailJIT = nil
		return JITConfig{}, err
	}
	f.nextID++
	f.Runners[f.nextID] = runnerName
	f.JITs = append(f.JITs, runnerName)
	return JITConfig{RunnerID: f.nextID, RunnerName: runnerName, Encoded: []byte(fmt.Sprintf("jit-for-%s-%d", runnerName, f.nextID))}, nil
}

// RemoveRunner implements ScaleSets.
func (f *Fake) RemoveRunner(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removeError != nil {
		return f.removeError
	}
	if err := f.busyRunners[id]; err != nil {
		return err
	}
	delete(f.Runners, id)
	f.Removed = append(f.Removed, id)
	return nil
}

// SetRemoveError makes removals fail until cleared, for cleanup retry tests.
func (f *Fake) SetRemoveError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeError = err
}

// RunnerByName implements ScaleSets.
func (f *Fake) RunnerByName(_ context.Context, name string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, n := range f.Runners {
		if n == name {
			return id, nil
		}
	}
	return 0, nil
}

// AcquiredIDs returns the request IDs acquired so far.
func (f *Fake) AcquiredIDs() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.Acquired...)
}

// JITNames returns the runner names that received a JIT config so far.
func (f *Fake) JITNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.JITs...)
}

// Registered reports whether a runner name is still registered.
func (f *Fake) Registered(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.Runners {
		if n == name {
			return true
		}
	}
	return false
}

// Closed reports whether the last session was closed.
func (f *Fake) Closed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

type fakeSession struct {
	f *Fake
}

func (s *fakeSession) Poll(ctx context.Context, _, _ int) (*Message, error) {
	select {
	case m := <-s.f.queue:
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *fakeSession) Ack(context.Context, int) error { return nil }

func (s *fakeSession) Acquire(_ context.Context, ids []int64) ([]int64, error) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	s.f.Acquired = append(s.f.Acquired, ids...)
	return ids, nil
}

func (s *fakeSession) Statistics() *Statistics {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	st := s.f.stats
	return &st
}

func (s *fakeSession) Close(context.Context) error {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	s.f.closed = true
	return nil
}

// JobAvailable builds a JobAvailable message body for tests.
func JobAvailable(requestID int64, repo string) *scaleset.JobAvailable {
	j := &scaleset.JobAvailable{}
	j.MessageType = scaleset.MessageTypeJobAvailable
	j.RunnerRequestID = requestID
	j.RepositoryName = repo
	j.OwnerName = "example-org"
	j.JobDisplayName = "macOS aarch64"
	return j
}

// JobStarted builds a JobStarted message body for tests.
func JobStarted(requestID int64, runnerName string) *scaleset.JobStarted {
	j := &scaleset.JobStarted{RunnerName: runnerName}
	j.MessageType = scaleset.MessageTypeJobStarted
	j.RunnerRequestID = requestID
	j.WorkflowRunID = requestID * 1000
	return j
}

// JobAssigned builds a JobAssigned message body for tests; its run ID is
// requestID*1000, matching JobStarted.
func JobAssigned(requestID int64) *scaleset.JobAssigned {
	j := &scaleset.JobAssigned{}
	j.MessageType = scaleset.MessageTypeJobAssigned
	j.RunnerRequestID = requestID
	j.WorkflowRunID = requestID * 1000
	return j
}

// JobCompleted builds a JobCompleted message body for tests.
func JobCompleted(requestID int64, runnerName, result string) *scaleset.JobCompleted {
	j := &scaleset.JobCompleted{RunnerName: runnerName, Result: result}
	j.MessageType = scaleset.MessageTypeJobCompleted
	j.RunnerRequestID = requestID
	return j
}

// Check implements JITRunners.
func (f *Fake) Check(context.Context, string) error { return nil }

// GenerateRunnerJIT implements JITRunners.
func (f *Fake) GenerateRunnerJIT(ctx context.Context, name, _ string, _ []string, work string) (JITConfig, error) {
	return f.GenerateJIT(ctx, 0, name, work)
}

// SetRunnerRemoveError makes one registration remain busy until cleared.
func (f *Fake) SetRunnerRemoveError(id int64, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.busyRunners[id] = err
}

// SetQueuedJobs replaces the complete workflow-job snapshot used by queued mode.
func (f *Fake) SetQueuedJobs(jobs []QueuedJob, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queuedJobs = append([]QueuedJob(nil), jobs...)
	f.queueError = err
}

// QueuedJobs implements JobQueue without opening a scale-set session.
func (f *Fake) QueuedJobs(ctx context.Context, _ []string) ([]QueuedJob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]QueuedJob(nil), f.queuedJobs...), f.queueError
}
