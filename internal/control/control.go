// Package control is the channel between the CLI and the daemon: a durable
// mode file, a pid file for waking the daemon, and a status snapshot the
// daemon rewrites on every change.
package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/state"
)

// Mode is the operator's intent. It survives reboots.
type Mode string

const (
	// ModeOn accepts jobs.
	ModeOn Mode = "on"
	// ModeDrain accepts no new jobs, lets active jobs finish, disposes of
	// their guests, then idles with the daemon still running.
	ModeDrain Mode = "drain"
	// ModeStop cancels active execution, destroys guests, reclaims resources,
	// then idles with the daemon still running.
	ModeStop Mode = "stop"
	// ModeOff drains, then the daemon exits and stays down across reboots.
	ModeOff Mode = "off"
)

// Parse validates a mode string.
func Parse(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(s)); m {
	case ModeOn, ModeDrain, ModeStop, ModeOff:
		return m, nil
	default:
		return "", fmt.Errorf("unknown mode %q", s)
	}
}

// Files locates the control files in the state directory.
type Files struct {
	Dir string
}

func (f Files) mode() string     { return filepath.Join(f.Dir, "mode") }
func (f Files) pid() string      { return filepath.Join(f.Dir, "daemon.pid") }
func (f Files) status() string   { return filepath.Join(f.Dir, "status.json") }
func (f Files) lockPath() string { return filepath.Join(f.Dir, "daemon.lock") }

// ErrAlreadyRunning reports another daemon holding the lock.
var ErrAlreadyRunning = errors.New("another bivouac daemon holds the lock")

// lockWait bounds how long Acquire retries a contended lock. CLI liveness
// probes hold a shared lock only between two system calls, while a running
// daemon (or `vz cleanup`) holds it until it exits. Retrying for longer than
// any probe means a probe cannot make a starting daemon give up.
const lockWait = 2 * time.Second

func acquireRetrying(try func() (*Lock, error)) (*Lock, error) {
	deadline := time.Now().Add(lockWait)
	for {
		l, err := try()
		if !errors.Is(err, ErrAlreadyRunning) || !time.Now().Before(deadline) {
			return l, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ReadMode returns the durable mode; a missing file means off.
func (f Files) ReadMode() (Mode, error) {
	data, err := state.ReadFile(f.mode())
	if errors.Is(err, os.ErrNotExist) {
		return ModeOff, nil
	}
	if err != nil {
		return "", err
	}
	return Parse(strings.TrimSpace(string(data)))
}

// WriteMode records the operator's intent durably.
func (f Files) WriteMode(m Mode) error {
	return state.WriteAtomic(f.mode(), []byte(string(m)+"\n"), 0o600)
}

// WritePID records the daemon's pid.
func (f Files) WritePID(pid int) error {
	return state.WriteAtomic(f.pid(), []byte(strconv.Itoa(pid)+"\n"), 0o600)
}

// RemovePID clears the pid file.
func (f Files) RemovePID() error {
	err := os.Remove(f.pid())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// ReadPID returns the recorded daemon pid, or 0.
func (f Files) ReadPID() (int, error) {
	data, err := state.ReadFile(f.pid())
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// Guest is one active guest in the status snapshot.
type Guest struct {
	Instance string      `json:"instance"`
	Provider string      `json:"provider"`
	Phase    state.Phase `json:"phase"`
	Job      string      `json:"job,omitempty"`
	Age      string      `json:"age"`
}

// Budgets summarises capacity.
type Budgets struct {
	MaxInstances      int            `json:"max_instances"`
	MaxPendingCleanup int            `json:"max_pending_cleanup"`
	Active            int            `json:"active"`
	Capacity          map[string]int `json:"capacity"` // per provider, runners it could still start
	Foreign           int            `json:"foreign_running"`
}

// Status is the daemon's snapshot.
type Status struct {
	PID            int           `json:"pid"`
	Mode           Mode          `json:"mode"`
	Phase          string        `json:"phase"` // polling, draining, stopping, idle, exiting
	UpdatedAt      time.Time     `json:"updated_at"`
	Guests         []Guest       `json:"guests"`
	PendingCleanup []Guest       `json:"pending_cleanup,omitempty"`
	Budgets        Budgets       `json:"budgets"`
	LastErrors     []state.Error `json:"last_errors,omitempty"`
	Unmanaged      []string      `json:"unmanaged_prefixed,omitempty"`
}

// WriteStatus replaces the snapshot. Free-form error text (the phase can
// carry a startup error) is redacted and bounded first.
func (f Files) WriteStatus(s *Status) error {
	s.UpdatedAt = time.Now()
	s.Phase = state.Message(s.Phase)
	errs := make([]state.Error, len(s.LastErrors))
	for i, e := range s.LastErrors {
		e.Message = state.Message(e.Message)
		errs[i] = e
	}
	if s.LastErrors != nil {
		s.LastErrors = errs
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return state.WriteAtomic(f.status(), data, 0o600)
}

// ReadStatus returns the last snapshot, or nil when the daemon never wrote one.
func (f Files) ReadStatus() (*Status, error) {
	data, err := state.ReadFile(f.status())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
