//go:build windows

package hcsspike

import "time"

// Timing values are host monotonic elapsed milliseconds, never guest wall time.
// Nested groups overlap: preparation and guest details subdivide lifecycle
// spans; total includes image hashing and cleanup. Zero can mean an
// unvisited stage or a stage shorter than one millisecond.
type Timings struct {
	ToValidatedDesktopMS uint64             `json:"to_validated_desktop"`
	TotalMS              uint64             `json:"total"`
	BaselineVerifyMS     uint64             `json:"baseline_verify"`
	Lifecycle            LifecycleTimings   `json:"lifecycle"`
	Preparation          PreparationTimings `json:"preparation"`
	Guest                GuestTimings       `json:"guest"`
}

type LifecycleTimings struct {
	PrepareMS   uint64 `json:"prepare"`
	CreateMS    uint64 `json:"create"`
	StartMS     uint64 `json:"start"`
	GPUAssignMS uint64 `json:"gpu_assign"`
	ProbeMS     uint64 `json:"probe"`
	CleanupMS   uint64 `json:"cleanup"`
}

type PreparationTimings struct {
	CloneMS         uint64 `json:"clone"`
	SetupAssetsMS   uint64 `json:"setup_assets"`
	SetupISOMS      uint64 `json:"setup_iso"`
	OfflineAnswerMS uint64 `json:"offline_answer"`
	DriverCopyMS    uint64 `json:"driver_copy"`
	PayloadGrantsMS uint64 `json:"payload_grants"`
}

type GuestTimings struct {
	BootEventsMS      uint64 `json:"boot_events,omitempty"`
	AgentConnectMS    uint64 `json:"agent_connect"`
	AgentInitializeMS uint64 `json:"agent_initialize"`
	SSHAuthenticateMS uint64 `json:"ssh_authenticate"`
	SSHChecksMS       uint64 `json:"ssh_checks"`
	DesktopValidateMS uint64 `json:"desktop_validate"`
	// These are host receipt intervals between fixed SSH checkpoints. Buffering
	// and transport scheduling can contribute; they are not guest CPU timings.
	ConsoleWaitMS      uint64 `json:"console_wait"`
	GPUDeviceWaitMS    uint64 `json:"gpu_device_wait"`
	InteractiveProbeMS uint64 `json:"interactive_probe"`
}

func elapsedMS(start time.Time) uint64 {
	return durationMS(time.Since(start))
}

func durationMS(elapsed time.Duration) uint64 {
	if elapsed <= 0 {
		return 0
	}
	return uint64(elapsed / time.Millisecond) // #nosec G115 -- Positive duration divided into milliseconds cannot overflow uint64.
}
