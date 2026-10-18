package crosvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
)

const preparedHelper = "/usr/local/libexec/bivouac-guest"
const runtimeHelper = "/tmp/bivouac-runner/helper"

type guestCommands interface {
	Output(context.Context, string, []string) ([]byte, error)
	OutputLimit(context.Context, string, []string, int) ([]byte, error)
	Input(context.Context, string, []string, []byte) ([]byte, error)
}

// Startup observations contain fixed booleans/counts only, never command data.
type GuestPreparation struct {
	FailedStage        uint32      `json:"failed_stage,omitempty"`
	DNSFailure         uint32      `json:"dns_failure,omitempty"`
	Config             GuestConfig `json:"config"`
	DNSReused          bool        `json:"dns_reused"`
	DNSProfileChanged  bool        `json:"dns_profile_changed"`
	DNSResolverChanged bool        `json:"dns_resolver_changed"`
	DNSMS              int64       `json:"dns_ms"`
	HelperInstallMS    int64       `json:"helper_install_ms"`
	TotalMS            int64       `json:"total_ms"`
}

func logStartup(name, stage string, started time.Time, err error, attrs ...any) {
	fields := []any{"instance", name, "stage", stage, "duration_ms", time.Since(started).Milliseconds(), "success", err == nil}
	slog.Info("linux startup stage", append(fields, attrs...)...)
}

type ImagePreparationRequest struct {
	Name         string `json:"name"`
	ControllerID string `json:"controller_id"`
	BootID       string `json:"boot_id"`
	HelperSHA256 string `json:"helper_sha256"`
}
type PreparedLinuxImage struct {
	FailedStage        uint32 `json:"failed_stage,omitempty"`
	HelperSHA256       string `json:"helper_sha256"`
	RunnerUnconfigured bool   `json:"runner_unconfigured"`
	DNSPrepared        bool   `json:"dns_prepared"`
	MachineIDCleared   bool   `json:"machine_id_cleared"`
	SSHHostKeysRemoved bool   `json:"ssh_host_keys_removed"`
}

func decodeGuestPreparation(data []byte, want GuestConfig, preparedOnly bool) (GuestPreparation, error) {
	var r GuestPreparation
	if len(data) > 4096 {
		return r, errors.New("linux preparation report exceeds bound")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
		return r, errors.New("invalid linux preparation report")
	}
	if r.FailedStage > 0 && r.FailedStage <= 8 && r.DNSFailure <= 11 {
		return r, fmt.Errorf("linux preparation refused at stage %d (DNS stage %d)", r.FailedStage, r.DNSFailure)
	}
	if r.FailedStage != 0 || r.DNSFailure != 0 || r.Config.Name != want.Name || r.Config.ControllerID != want.ControllerID || r.Config.RunnerDir != want.RunnerDir || r.Config.GPU != want.GPU || len(r.Config.BootID) != 36 || r.DNSMS < 0 || r.HelperInstallMS < 0 || r.TotalMS < r.DNSMS || r.TotalMS < r.HelperInstallMS || r.TotalMS > 720000 || r.DNSReused && (r.DNSProfileChanged || r.DNSResolverChanged) {
		return r, errors.New("generic linux guest readiness was not proven")
	}
	if preparedOnly && !r.DNSReused {
		return r, errors.New("prepared image DNS reuse was not proven")
	}
	return r, nil
}
