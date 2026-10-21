// Package provider defines the contract between bivouac's portable core and
// a virtualization engine. Launch options are argument arrays or structured
// fields, never shell strings.
package provider

import (
	"context"
	"errors"
	"io"
	"time"
)

// GPUMode is how a guest reaches a GPU.
type GPUMode string

const (
	GPUNone            GPUMode = "none"
	GPUParavirtualized GPUMode = "paravirtualized"
	GPUPassthrough     GPUMode = "passthrough"
)

// Capabilities are explicit and provider-specific.
type Capabilities struct {
	GPU GPUMode
	// DesktopSession reports whether the runner starts inside a logged-in
	// desktop session (required for windowed and focus tests).
	DesktopSession bool
	// DisplayTransport names how a display reaches the host, or "none".
	DisplayTransport string
	// HostLimit is the engine's own ceiling on concurrent guests per host, or
	// 0 for none. Apple's Virtualization framework allows two macOS guests.
	HostLimit int
	// OperationTimeout is the longest one Status, Stop (beyond its graceful
	// period) or Delete call may legitimately take, or 0 for the manager's
	// default. The manager bounds those calls by the larger of the two, so it
	// never abandons an operation the engine is still allowed to finish.
	OperationTimeout time.Duration
}

// Metadata is written into the engine's own records for an instance, so a
// later process can prove ownership before deleting anything.
type Metadata struct {
	ParentName    string `json:"parent_name,omitempty"`
	EngineName    string `json:"engine_name,omitempty"`
	NetworkPolicy string `json:"network_policy,omitempty"`
	ControllerID  string `json:"controller_id"`
	InstanceID    string `json:"instance_id"`
	CreatedAt     string `json:"created_at"`
}

// Launch holds provider-specific launch options. CLI providers use Args;
// API providers use Fields. Neither is ever joined into a shell string.
type Launch struct {
	Args   []string
	Fields map[string]string
}

// Spec describes a disposable instance to create from a named baseline.
type Spec struct {
	// Name is unique, carries the bivouac prefix, and doubles as runner name.
	Name     string
	Baseline string
	CPU      int // 0 keeps the baseline's value
	MemoryMB int // 0 keeps the baseline's value
	Launch   Launch
	Meta     Metadata
}

// Status is a point-in-time view of an instance.
type Status struct {
	Exists  bool
	Running bool
	// Owned is true when the engine's metadata carries our controller ID.
	Owned bool
	Meta  Metadata
}

// Owned is an instance the provider recognises as bivouac's.
type Owned struct {
	Name    string
	Running bool
	Meta    Metadata
}

// Foreign is a guest bivouac does not own. A running one still consumes a
// host slot; a prefixed one is reported but never touched.
type Foreign struct {
	Name     string
	Running  bool
	Prefixed bool // carries the bivouac prefix without our metadata
}

// RunnerState is what the guest reports about the runner process.
type RunnerState string

const (
	RunnerAbsent    RunnerState = "absent"
	RunnerStarting  RunnerState = "starting" // process up, not yet connected
	RunnerRunning   RunnerState = "running"  // executing a job
	RunnerListening RunnerState = "listening"
	RunnerExited    RunnerState = "exited"
)

// RunnerStatus is the runner's state plus its exit code once it exited.
// RunnerJob is the non-secret identity reported by the official job-start hook.
type RunnerJob struct {
	RunID      int64
	Repository string
	Name       string
}

type RunnerStatus struct {
	Job      *RunnerJob
	State    RunnerState
	ExitCode int
}

// ErrNotFound reports an instance the engine does not know.
var ErrNotFound = errors.New("instance not found")

// ErrNotOwned reports an instance that exists but does not carry our
// metadata; it must never be stopped or deleted.
var ErrNotOwned = errors.New("instance not owned by this controller")

// Provider manages disposable instances on one engine. Methods are safe for
// concurrent use with distinct names.
type Provider interface {
	Name() string
	Capabilities() Capabilities

	// Create makes a disposable instance from the baseline and records Meta.
	Create(ctx context.Context, spec Spec) error
	// Start boots the instance. Launch output is written to launchLog.
	Start(ctx context.Context, name string, launchLog io.Writer) error
	// WaitReady blocks until the guest can run commands.
	WaitReady(ctx context.Context, name string) error
	// StartRunner delivers the JIT config over a private channel (stdin or a
	// mode-0600 file) and starts the official runner once in the guest's
	// desktop session. The config never appears on a command line.
	StartRunner(ctx context.Context, name string, jitConfig []byte) error
	// StopRunner asks the official runner to cancel its job and report the
	// result before the guest is stopped. ctx bounds the grace period.
	StopRunner(ctx context.Context, name string) error
	// RunnerStatus reports the runner process. TransportFailure allows bounded
	// retries of guest transport errors; ownership, isolation and status-decoding
	// errors remain terminal. Repeat ownership/isolation checks on every probe.
	RunnerStatus(ctx context.Context, name string) (RunnerStatus, error)
	// Status reports the instance.
	Status(ctx context.Context, name string) (Status, error)
	// Stop shuts the instance down, gracefully within timeout, then by force.
	Stop(ctx context.Context, name string, timeout time.Duration) error
	// Delete removes the instance. It fails with ErrNotOwned unless the
	// engine's metadata proves ownership.
	Delete(ctx context.Context, name string) error
	// List returns the instances this provider owns and the running guests it
	// does not.
	List(ctx context.Context) ([]Owned, []Foreign, error)
	// CollectDiagnostics copies the runner's _diag logs and runner output from
	// the guest into dir.
	CollectDiagnostics(ctx context.Context, name string, dir string) error
}

// Activator is implemented by providers whose host runtime is needed while CI
// is on. Calls are bounded by the manager's context.
type Activator interface {
	// Activate makes the runtime serve this provider, starting it if needed.
	// It is idempotent and checks that the runtime can serve this provider.
	Activate(ctx context.Context) error
	// Deactivate stops a runtime this provider can stop, only when it has no
	// instances from any caller. A runtime it cannot stop is left alone.
	Deactivate(ctx context.Context) error
}
