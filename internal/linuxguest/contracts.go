package linuxguest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const PreparedHelper = "/usr/local/libexec/bivouac-guest"
const RuntimeHelper = "/tmp/bivouac-runner/helper"

// Startup observations contain fixed booleans/counts only, never command data.
type GuestPreparation struct {
	FailedStage        uint32      `json:"failed_stage,omitempty"`
	DNSFailure         uint32      `json:"dns_failure,omitempty"`
	Config             GuestConfig `json:"config"`
	DNSDHCP            bool        `json:"dns_dhcp"`
	DNSReused          bool        `json:"dns_reused"`
	DNSProfileChanged  bool        `json:"dns_profile_changed"`
	DNSResolverChanged bool        `json:"dns_resolver_changed"`
	DNSMS              int64       `json:"dns_ms"`
	HelperInstallMS    int64       `json:"helper_install_ms"`
	TotalMS            int64       `json:"total_ms"`
}

type ImagePreparationRequest struct {
	Profile      ExecutionProfile `json:"profile"`
	Name         string           `json:"name"`
	ControllerID string           `json:"controller_id"`
	BootID       string           `json:"boot_id"`
	HelperSHA256 string           `json:"helper_sha256"`
}
type PreparedLinuxImage struct {
	Profile            ExecutionProfile `json:"profile"`
	DNSDHCP            bool             `json:"dns_dhcp"`
	FailedStage        uint32           `json:"failed_stage,omitempty"`
	HelperSHA256       string           `json:"helper_sha256"`
	RunnerUnconfigured bool             `json:"runner_unconfigured"`
	DNSPrepared        bool             `json:"dns_prepared"`
	MachineIDCleared   bool             `json:"machine_id_cleared"`
	SSHHostKeysRemoved bool             `json:"ssh_host_keys_removed"`
}

func DecodeGuestPreparation(data []byte, want GuestConfig, preparedOnly bool) (GuestPreparation, error) {
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
	if want.Profile.Validate() != nil || r.Config.Profile != want.Profile || r.FailedStage != 0 || r.DNSFailure != 0 || r.Config.Name != want.Name || r.Config.ControllerID != want.ControllerID || r.Config.RunnerDir != want.RunnerDir || r.Config.GPU != want.GPU || len(r.Config.BootID) != 36 || r.DNSMS < 0 || r.HelperInstallMS < 0 || r.TotalMS < r.DNSMS || r.TotalMS < r.HelperInstallMS || r.TotalMS > 720000 || r.DNSReused && (r.DNSProfileChanged || r.DNSResolverChanged) {
		return r, errors.New("generic linux guest readiness was not proven")
	}
	if want.Profile == VZ && (!r.DNSDHCP || r.DNSReused || r.DNSProfileChanged || r.DNSResolverChanged) || want.Profile == Crosvm && r.DNSDHCP {
		return r, errors.New("linux preparation DNS profile differs")
	}
	if preparedOnly && want.Profile == Crosvm && !r.DNSReused {
		return r, errors.New("prepared image DNS reuse was not proven")
	}
	return r, nil
}

// DecodePreparedImage validates a bounded sanitation receipt or durable marker.
// VZ reports DHCP delegation, never forced-public DNS or SSH sanitation.
func DecodePreparedImage(data []byte, profile ExecutionProfile, hash string) (PreparedLinuxImage, error) {
	var r PreparedLinuxImage
	if profile.Validate() != nil || !digest(hash) || len(data) > 4096 {
		return r, errors.New("invalid image preparation contract")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
		return r, errors.New("invalid linux image preparation report")
	}
	if r.FailedStage > 0 && r.FailedStage <= 17 {
		return r, fmt.Errorf("image preparation refused at stage %d", r.FailedStage)
	}
	if r.FailedStage != 0 || r.Profile != profile || r.HelperSHA256 != hash || !r.RunnerUnconfigured || !r.MachineIDCleared || r.DNSPrepared != (profile == Crosvm) || r.DNSDHCP != (profile == VZ) || r.SSHHostKeysRemoved != profile.sshSanitation() {
		return r, errors.New("image trial sanitation was not proven")
	}
	return r, nil
}
