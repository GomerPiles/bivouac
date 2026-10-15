// Package state is bivouac's durable record of what it created. Every
// instance and runner identity is written here before the engine or GitHub
// learns of it, so recovery can reconcile and clean up after a crash.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/GomerPiles/bivouac/internal/redact"
)

// Phase is where an instance is in its lifecycle.
type Phase string

const (
	PhaseCreating      Phase = "creating"
	PhaseBooting       Phase = "booting"
	PhaseReady         Phase = "ready"
	PhaseListening     Phase = "listening" // runner registered, waiting for a job
	PhaseRunning       Phase = "running"   // job in progress
	PhaseFinished      Phase = "finished"  // runner exited
	PhaseCollecting    Phase = "collecting"
	PhaseDestroying    Phase = "destroying"
	PhaseDeregistering Phase = "deregistering" // VM deletion confirmed; runner cleanup pending
	PhaseFailed        Phase = "failed"
)

// Terminal reports whether the instance needs no more work after teardown.
func (p Phase) Terminal() bool { return p == PhaseFailed }

// Job identifies the GitHub job an instance served.
type Job struct {
	RequestID   int64     `json:"request_id"`
	Owner       string    `json:"owner"`
	Repository  string    `json:"repository"`
	WorkflowRef string    `json:"workflow_ref"`
	DisplayName string    `json:"display_name"`
	RunID       int64     `json:"run_id"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	FinishedAt  time.Time `json:"finished_at,omitempty"`
	Result      string    `json:"result,omitempty"`
}

// Timings records per-job overhead in milliseconds.
type Timings struct {
	CloneMS    int64 `json:"clone_ms"`
	BootMS     int64 `json:"boot_ms"`     // start to guest ready
	RegisterMS int64 `json:"register_ms"` // JIT generated to runner listening
	TeardownMS int64 `json:"teardown_ms"` // diagnostics, stop, delete
}

// Instance is one disposable guest and its runner identity.
type Instance struct {
	ID              string    `json:"id"`
	Provider        string    `json:"provider"`
	Name            string    `json:"name"`                  // VM name and runner name
	EngineName      string    `json:"engine_name,omitempty"` // recorded before either clone
	ContainerEngine string    `json:"container_engine,omitempty"`
	CPU             int       `json:"cpu,omitempty"` // full pair reservation, frozen at admission
	MemoryGB        int       `json:"memory_gb,omitempty"`
	RunnerID        int64     `json:"runner_id,omitempty"`
	ScaleSetID      int       `json:"scale_set_id,omitempty"`
	Phase           Phase     `json:"phase"`
	Job             *Job      `json:"job,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	ListenedAt      time.Time `json:"listened_at,omitempty"`
	GuestDeletedAt  time.Time `json:"guest_deleted_at,omitempty"`
	CleanupPending  bool      `json:"cleanup_pending,omitempty"` // deregistration has failed and needs retry
	// Sweep marks a runner started without an assigned job, to collect jobs
	// GitHub routed by label while no session was open.
	Sweep      bool     `json:"sweep,omitempty"`
	LaunchArgs []string `json:"launch_args,omitempty"`
	LastError  string   `json:"last_error,omitempty"`
	DiagDir    string   `json:"diag_dir,omitempty"`
	Timings    Timings  `json:"timings"`
}

// clone returns a deep copy so callers never share the Job or LaunchArgs
// with the stored record.
func (i *Instance) clone() Instance {
	cp := *i
	if i.Job != nil {
		j := *i.Job
		cp.Job = &j
	}
	cp.LaunchArgs = append([]string(nil), i.LaunchArgs...)
	return cp
}

// File is the on-disk document.
type File struct {
	ControllerID string               `json:"controller_id"`
	Instances    map[string]*Instance `json:"instances"`
	// Errors keeps the most recent failures for `status`.
	Errors []Error `json:"errors,omitempty"`
}

// Error is a recorded failure.
type Error struct {
	At       time.Time `json:"at"`
	Instance string    `json:"instance,omitempty"`
	Message  string    `json:"message"`
}

const maxErrors = 20

// MaxMessage bounds one error message in state and status. SDK errors can
// carry request URLs and whole response bodies.
const MaxMessage = 1024

// Message prepares free-form error text for a durable file: credentials are
// redacted and the result is cut to MaxMessage bytes on a rune boundary.
func Message(s string) string {
	s = redact.String(s)
	if len(s) <= MaxMessage {
		return s
	}
	const more = " [truncated]"
	cut := MaxMessage - len(more)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + more
}

// Store owns the file and serialises access.
type Store struct {
	path string
	mu   sync.Mutex
	file File
}

// Path is the durable record path used by the detached, ownership-checked relay.
func (s *Store) Path() string { return s.path }

// Open loads or creates the store at dir/instances.json. A new store gets a
// fresh controller ID.
func Open(dir string, newID func() string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "instances.json")}
	data, err := ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.file = File{ControllerID: newID(), Instances: map[string]*Instance{}}
		if err := s.save(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, &s.file); err != nil {
			return nil, fmt.Errorf("state %s: %w", s.path, err)
		}
		if s.file.Instances == nil {
			s.file.Instances = map[string]*Instance{}
		}
		if s.file.ControllerID == "" {
			s.file.ControllerID = newID()
		}
	}
	return s, nil
}

// ControllerID identifies this bivouac installation in provider metadata.
func (s *Store) ControllerID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.ControllerID
}

// Put inserts or replaces an instance and persists.
func (s *Store) Put(inst *Instance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := inst.clone()
	cp.UpdatedAt = time.Now()
	cp.LastError = Message(cp.LastError)
	s.file.Instances[cp.ID] = &cp
	return s.save()
}

// Update applies fn to the stored instance and persists. It returns a copy.
func (s *Store) Update(id string, fn func(*Instance)) (*Instance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.file.Instances[id]
	if !ok {
		return nil, fmt.Errorf("state: unknown instance %s", id)
	}
	updated := inst.clone()
	fn(&updated)
	updated.UpdatedAt = time.Now()
	updated.LastError = Message(updated.LastError)
	s.file.Instances[id] = &updated
	if err := s.save(); err != nil {
		s.file.Instances[id] = inst
		return nil, err
	}
	cp := updated.clone()
	return &cp, nil
}

// Remove deletes the record once the guest and runner are gone.
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, exists := s.file.Instances[id]
	delete(s.file.Instances, id)
	if err := s.save(); err != nil {
		if exists {
			s.file.Instances[id] = inst
		}
		return err
	}
	return nil
}

// Get returns a copy of one instance.
func (s *Store) Get(id string) (*Instance, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.file.Instances[id]
	if !ok {
		return nil, false
	}
	cp := inst.clone()
	return &cp, true
}

// List returns copies of every instance, oldest first.
func (s *Store) List() []*Instance {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Instance, 0, len(s.file.Instances))
	for _, inst := range s.file.Instances {
		cp := inst.clone()
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// RecordError keeps a bounded list of recent failures. The message is
// redacted and bounded. Repeating an instance's most recent message changes
// nothing, so a retry loop neither rewrites the file nor pushes other
// failures out of the ring.
func (s *Store) RecordError(instance, msg string) error {
	msg = Message(msg)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.file.Errors) - 1; i >= 0; i-- {
		if e := s.file.Errors[i]; e.Instance == instance {
			if e.Message == msg {
				return nil
			}
			break
		}
	}
	s.file.Errors = append(s.file.Errors, Error{At: time.Now(), Instance: instance, Message: msg})
	if len(s.file.Errors) > maxErrors {
		s.file.Errors = s.file.Errors[len(s.file.Errors)-maxErrors:]
	}
	return s.save()
}

// Errors returns recent failures, oldest first.
func (s *Store) Errors() []Error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Error(nil), s.file.Errors...)
}

// save writes atomically: temp file, fsync, rename.
func (s *Store) save() error {
	data, err := json.MarshalIndent(&s.file, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(s.path, data, 0o600)
}

// WriteAtomic replaces path with data via a temp file and rename.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		cleanup()
		return err
	}
	if err := replaceFile(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
