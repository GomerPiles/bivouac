//go:build windows

package vmhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// PipeName is the VM host's only endpoint. Its DACL admits SYSTEM,
// Administrators and the configured accounts; clients also verify that the
// server is elevated, so an unprivileged squatter cannot impersonate it.
const PipeName = `\\.\pipe\bivouac-vmhost`

const (
	maxRequest  = 64 << 10
	maxResponse = 1 << 20
)

// Request is one operation; each pipe connection carries exactly one.
type Request struct {
	Op     string         `json:"op"` // info, create, status, destroy or list
	Name   string         `json:"name,omitempty"`
	Create *CreateRequest `json:"create,omitempty"`
}

// CreateRequest names a configured image rather than a path. The VM host,
// not the caller, decides which account each HvSocket service admits.
type CreateRequest struct {
	Name       string            `json:"name"`
	Image      string            `json:"image"`
	CPU        uint32            `json:"cpu"`
	MemoryMB   uint64            `json:"memory_mb"`
	LazyMemory bool              `json:"lazy_memory,omitempty"`
	GPU        bool              `json:"gpu"`
	Network    bool              `json:"network,omitempty"`
	Services   []string          `json:"services,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// Error codes let callers act on a failure without parsing its text.
const (
	CodeRefused  = "refused"         // invalid, unauthorized or over a limit
	CodeNotFound = "not_found"       // no such guest for this caller
	CodeForeign  = "foreign"         // ownership unproven; nothing touched
	CodeUnknown  = "outcome_unknown" // a mutation may still complete
	CodeFailed   = "failed"
)

type Response struct {
	Code   string      `json:"code,omitempty"`
	Error  string      `json:"error,omitempty"`
	Guest  *GuestInfo  `json:"guest,omitempty"`
	Guests []GuestInfo `json:"guests,omitempty"`
	Info   *Info       `json:"info,omitempty"`
}

// GuestInfo is a guest as its owner sees it. State is running, stopped or absent.
type GuestInfo struct {
	Name      string            `json:"name"`
	RuntimeID string            `json:"runtime_id,omitempty"`
	State     string            `json:"state"`
	TimingsMS map[string]int64  `json:"timings_ms,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	// Network is the guest's isolated endpoint, or nil while the VM host
	// attaches none.
	Network *NetworkLease `json:"network,omitempty"`
	// ProtectedBeforeStart, reported on create, says the port policy was in
	// place before the guest's first instruction rather than right after.
	ProtectedBeforeStart bool `json:"protected_before_start,omitempty"`
}

// NetworkLease is the static IPv4 configuration the guest must apply to the
// adapter with MAC.
type NetworkLease struct {
	Address string `json:"address"`
	Gateway string `json:"gateway"`
	Prefix  int    `json:"prefix"`
	MAC     string `json:"mac"`
}

// Info reports the VM host's identity and limits. Running counts every
// caller's guests, so each manager can budget against the shared host.
type Info struct {
	Controller   string   `json:"controller"`
	Images       []string `json:"images"`
	MaxInstances int      `json:"max_instances"`
	MaxCPU       uint32   `json:"max_cpu"`
	MaxMemoryMB  uint64   `json:"max_memory_mb"`
	Running      int      `json:"running"`
	RunningCPU   uint32   `json:"running_cpu"`
	RunningMB    uint64   `json:"running_memory_mb"`
}

const (
	StateRunning = "running"
	StateStopped = "stopped"
	StateAbsent  = "absent"
)

// Config is the VM host's administrator-protected configuration. Every value
// bounds what unprivileged callers can ask for.
type Config struct {
	Root         string            `json:"root"`
	Controller   string            `json:"controller"`
	Accounts     []string          `json:"accounts"`
	Images       map[string]string `json:"images"`
	MaxInstances int               `json:"max_instances"`
	MaxCPU       uint32            `json:"max_cpu"`
	MaxMemoryMB  uint64            `json:"max_memory_mb"`
}

var imageName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func (c Config) Validate() error {
	if !localAbsolute(c.Root) || !controllerPattern.MatchString(c.Controller) {
		return errors.New("VM host config needs a local absolute root and a controller identity")
	}
	if len(c.Accounts) == 0 || len(c.Accounts) > 8 {
		return errors.New("VM host config needs 1-8 accounts")
	}
	for _, sid := range c.Accounts {
		if !sidPattern.MatchString(sid) {
			return errors.New("VM host accounts must be SID strings")
		}
	}
	if len(c.Images) == 0 || len(c.Images) > 16 {
		return errors.New("VM host config needs 1-16 images")
	}
	for name, path := range c.Images {
		if !imageName.MatchString(name) || !localAbsolute(path) || !strings.EqualFold(filepath.Ext(path), ".vhdx") {
			return errors.New("VM host images map short names to local absolute VHDX paths")
		}
	}
	if c.MaxInstances < 1 || c.MaxInstances > 16 || c.MaxCPU < 1 || c.MaxCPU > 256 || c.MaxMemoryMB < 1024 || c.MaxMemoryMB > 1<<20 {
		return errors.New("VM host limits: 1-16 instances, 1-256 CPUs, 1024-1048576 MiB")
	}
	return nil
}

// DecodeConfig reads one bounded JSON object with no unknown fields.
func DecodeConfig(r io.Reader) (Config, error) {
	var c Config
	b, err := io.ReadAll(io.LimitReader(r, maxRequest+1))
	if err != nil || len(b) > maxRequest {
		return c, errors.New("VM host config unreadable or too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errors.New("invalid VM host config")
	}
	return c, c.Validate()
}

func durations(t Timings) map[string]int64 {
	ms := func(d time.Duration) int64 { return d.Milliseconds() }
	return map[string]int64{"disk": ms(t.Disk), "state_files": ms(t.StateFiles), "grants": ms(t.Grants), "network": ms(t.Network), "create": ms(t.Create), "protect": ms(t.Protect), "start": ms(t.Start), "gpu": ms(t.GPU)}
}
