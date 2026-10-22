// Package imagefactory prepares standalone Windows HCS images in an owned,
// administrator-protected workspace. It never uses the VM host service journal.
package imagefactory

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/winguest"
)

type PinnedFile struct {
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
}

type Asset struct {
	Name string `json:"name"`
	PinnedFile
}

type Config struct {
	Source           string     `json:"source"`
	SourceSHA256     string     `json:"source_sha256"`
	ExpectedTemplate string     `json:"expected_template,omitempty"`
	GuestUser        string     `json:"guest_user"`
	CPU              uint32     `json:"cpu"`
	MemoryMB         uint64     `json:"memory_mb"`
	SetupAssets      []Asset    `json:"setup_assets"`
	RenderProbe      PinnedFile `json:"render_probe"`
	Drivers          []string   `json:"drivers"`
	ImageRoot        string     `json:"image_root"`
	TimeoutSeconds   int        `json:"timeout_seconds"`
}

// DecodeConfig rejects unknown fields and trailing input without returning
// decoder errors, which can contain arbitrary input text.
func DecodeConfig(r io.Reader) (Config, error) {
	var c Config
	b, err := io.ReadAll(io.LimitReader(r, 65537))
	if err != nil || len(b) > 65536 {
		return c, errors.New("image configuration exceeds 64 KiB or is unreadable")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return Config{}, errors.New("invalid image configuration JSON")
	}
	if c.CPU == 0 {
		c.CPU = 4
	}
	if c.MemoryMB == 0 {
		c.MemoryMB = 8192
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 900
	}
	return c, c.Validate()
}

func pin(s string) bool { b, e := hex.DecodeString(s); return e == nil && len(b) == 32 }
func localPath(s string) bool {
	if len(s) < 4 || len(s) > 240 || !asciiLetter(s[0]) || s[1] != ':' || s[2] != '\\' || strings.ContainsAny(s[3:], ":\x00\r\n\"<>|?*/~") {
		return false
	}
	for _, part := range strings.Split(s[3:], `\`) {
		if part == "" || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return false
		}
	}
	return true
}
func asciiLetter(b byte) bool { return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' }
func within(root, path string) bool {
	r := strings.ToLower(strings.TrimRight(root, `\`))
	p := strings.ToLower(path)
	return p == r || strings.HasPrefix(p, r+`\`)
}
func safeUser(s string) bool {
	if len(s) < 1 || len(s) > 20 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}
func (c Config) Validate() error {
	// Configured paths are Windows paths whatever the build's OS, so split
	// on backslashes rather than with filepath.
	sourceDir := c.Source[:max(strings.LastIndex(c.Source, `\`), 0)]
	if !localPath(c.Source) || !strings.HasSuffix(strings.ToLower(c.Source), ".vhdx") || !pin(c.SourceSHA256) || !localPath(c.ImageRoot) || len(strings.TrimRight(c.ImageRoot, `\`)) < 4 || within(c.ImageRoot, c.Source) || within(sourceDir, c.ImageRoot) {
		return errors.New("source and image root must be disjoint local absolute paths with a source SHA-256")
	}
	if !safeUser(c.GuestUser) || len(c.ExpectedTemplate) > 128 || strings.ContainsAny(c.ExpectedTemplate, "\\/:\x00\r\n") {
		return errors.New("invalid guest user or template name")
	}
	if c.CPU < 1 || c.CPU > 4 || c.MemoryMB < 1024 || c.MemoryMB > 8192 || c.TimeoutSeconds < 300 || c.TimeoutSeconds > 3600 {
		return errors.New("image build requires 1-4 CPU, 1024-8192 MiB and a 300-3600 second timeout")
	}
	validFile := func(f PinnedFile) bool { return localPath(f.Source) && !within(c.ImageRoot, f.Source) && pin(f.SHA256) }
	if !validFile(c.RenderProbe) || len(c.SetupAssets) < 3 || len(c.SetupAssets) > 5 {
		return errors.New("pinned render probe and bounded setup assets are required")
	}
	required := map[string]bool{"APPSANDBOX-AGENT.EXE": false, "APPSANDBOX-INPUT.EXE": false, "APPSANDBOX-DISPLAYS.EXE": false}
	seen := map[string]bool{}
	for _, a := range c.SetupAssets {
		n := strings.ToUpper(a.Name)
		_, known := required[n]
		if (!known && n != "OPENSSH.MSI" && n != "RUNNER.ZIP") || seen[n] || !validFile(a.PinnedFile) {
			return errors.New("unsupported, duplicate or unpinned setup asset")
		}
		seen[n] = true
		required[n] = true
	}
	for _, ok := range required {
		if !ok {
			return errors.New("agent and display/input helpers are required")
		}
	}
	if len(c.Drivers) < 1 || len(c.Drivers) > 8 {
		return errors.New("one to eight GPU driver directories are required")
	}
	seen = map[string]bool{}
	for _, d := range c.Drivers {
		n := strings.ToLower(d)
		if !localPath(d) || within(c.ImageRoot, d) || seen[n] || strings.ContainsAny(d, "|\n\r") {
			return errors.New("invalid GPU driver directory")
		}
		seen[n] = true
	}
	return nil
}

func validID(id string) bool {
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 16 && strings.ToLower(id) == id
}

// GuestName matches the spike's first-four-bytes base32 derivation.
func GuestName(id string) (string, error) {
	if !validID(id) {
		return "", errors.New("invalid image build ID")
	}
	b, _ := hex.DecodeString(id)
	return "bivouac-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:4])), nil
}

func hashBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type Inspection struct {
	FailureStep           uint32                   `json:"failure_step"`
	SystemHiveError       uint32                   `json:"system_hive_error"`
	SoftwareHiveError     uint32                   `json:"software_hive_error"`
	SystemSetupInProgress uint32                   `json:"system_setup_in_progress"`
	OOBEInProgress        uint32                   `json:"oobe_in_progress"`
	SetupPhase            uint32                   `json:"setup_phase"`
	ImageStateKind        string                   `json:"image_state_kind"`
	UnattendPointerKind   string                   `json:"unattend_pointer_kind"`
	AnswerDirectoryEmpty  bool                     `json:"answer_directory_empty"`
	PantherAnswerPresent  bool                     `json:"panther_answer_present"`
	PantherAnswer         *AnswerFacts             `json:"panther_answer,omitempty"`
	AgentService          *ServiceFact             `json:"agent_service,omitempty"`
	SSHService            *ServiceFact             `json:"sshd_service,omitempty"`
	Executables           map[string]string        `json:"executables"`
	VDDPresent            *bool                    `json:"vdd_present,omitempty"`
	VDDPackagePresent     *bool                    `json:"vdd_package_present,omitempty"`
	RunnerState           string                   `json:"runner_state"`
	RunnerResidue         map[string]RunnerResidue `json:"runner_residue"`
	RunnerVersion         string                   `json:"runner_version,omitempty"`
	BivouacPresent        bool                     `json:"bivouac_present"`
	BivouacSubdirectories []string                 `json:"bivouac_subdirectories"`
	GuestStatePresent     bool                     `json:"guest_state_present"`
	SAMHiveError          uint32                   `json:"sam_hive_error"`
	GuestUserExists       *bool                    `json:"guest_user_exists"`
	GuestSetupStep        uint32                   `json:"guest_setup_step"`
	GuestSetupFailed      bool                     `json:"guest_setup_failed"`
	GuestSetupVideo       *SetupVideoStatus        `json:"guest_setup_video,omitempty"`
}

// SetupVideoStatus contains only bounded numeric diagnostics, never device IDs.
type SetupVideoStatus struct {
	SpecializeBefore *SetupVideoSnapshot `json:"specialize_before,omitempty"`
	SpecializeAfter  *SetupVideoSnapshot `json:"specialize_after,omitempty"`
	FirstLogon       *SetupVideoSnapshot `json:"first_logon,omitempty"`
	SpecializeEnable *SetupVideoEnable   `json:"specialize_enable,omitempty"`
	FirstLogonEnable *SetupVideoEnable   `json:"first_logon_enable,omitempty"`
}

type SetupVideoSnapshot struct {
	NodeCount uint32           `json:"node_count"`
	Nodes     []SetupVideoNode `json:"nodes"`
}

type SetupVideoNode struct {
	Present              uint32 `json:"present"`
	ProblemCode          uint32 `json:"problem_code"`
	DevNodeStatus        uint32 `json:"devnode_status"`
	ConfigFlagsPresent   uint32 `json:"config_flags_present"`
	ConfigFlags          uint32 `json:"config_flags"`
	CSConfigFlagsPresent uint32 `json:"csconfig_flags_present"`
	CSConfigFlags        uint32 `json:"csconfig_flags"`
}

type SetupVideoEnable struct {
	Returned uint32              `json:"returned"`
	Attempts []SetupVideoAttempt `json:"attempts"`
}

type SetupVideoAttempt struct {
	NodeIndex         uint32 `json:"node_index"`
	FlagsCleared      uint32 `json:"flags_cleared"`
	PnPUtilStarted    uint32 `json:"pnputil_started"`
	PnPUtilExitCode   uint32 `json:"pnputil_exit_code"`
	FallbackAttempted uint32 `json:"fallback_attempted"`
	FallbackSucceeded uint32 `json:"fallback_succeeded"`
	Returned          uint32 `json:"returned"`
}

// AnswerFacts contains only predicates, never answer-file values or commands.
type AnswerFacts struct {
	SpecializePass     bool `json:"specialize_pass"`
	OOBESystemPass     bool `json:"oobe_system_pass"`
	GuestLocalAccount  bool `json:"guest_local_account"`
	AutologonPresent   bool `json:"autologon_present"`
	AutologonGuestUser bool `json:"autologon_guest_user"`
}

type RunnerResidue struct {
	Entries      []RunnerEntry `json:"entries"`
	OmittedNames uint64        `json:"omitted_names"`
	Truncated    bool          `json:"truncated"`
}

type RunnerEntry struct {
	Name      string `json:"name"`
	Directory bool   `json:"directory"`
}

type ServiceFact struct {
	Present           bool   `json:"present"`
	ImagePath         string `json:"image_path"`
	ImagePathRedacted bool   `json:"image_path_redacted"`
}

type InspectionReport struct {
	BuildID string      `json:"build_id"`
	Facts   *Inspection `json:"inspection"`
}

// PublishedError distinguishes a usable, committed image from a failed build.
type PublishedError struct {
	BuildID string
	Err     error
}

func (e *PublishedError) Error() string {
	return "image is published (build " + e.BuildID + "); workspace cleanup or record update failed: " + e.Err.Error()
}
func (e *PublishedError) Unwrap() error { return e.Err }

func (i Inspection) Generalized() bool {
	return i.FailureStep == 0 && i.SystemHiveError == 0 && i.SoftwareHiveError == 0 && i.SystemSetupInProgress == 1 && i.OOBEInProgress == 1 && i.ImageStateKind == "generalized_to_oobe" && (i.UnattendPointerKind == "absent" || i.UnattendPointerKind == "empty") && i.AnswerDirectoryEmpty
}

func (i Inspection) Eligible() bool {
	return i.Generalized() && !i.GuestStatePresent && (i.RunnerState == "absent" || i.RunnerState == "unconfigured" || i.diagLogsOnly())
}

// diagLogsOnly admits residue that is only regular files in _diag, such as
// logs from template preparation; guest setup removes them before its runner
// check. Anything in _work, any directory, or any omitted name stays refused.
func (i Inspection) diagLogsOnly() bool {
	if i.RunnerState != "residue" || len(i.RunnerResidue) != 1 {
		return false
	}
	diag, ok := i.RunnerResidue["_diag"]
	if !ok || diag.Truncated || diag.OmittedNames != 0 || len(diag.Entries) == 0 {
		return false
	}
	for _, e := range diag.Entries {
		if e.Directory {
			return false
		}
	}
	return true
}

// RunnerInput checks the conditional asset requirement after offline inspection,
// before any guest can be created. Inspect itself does not need setup media.
func (i Inspection) RunnerInput(c Config) error {
	if i.RunnerState != "absent" {
		return nil
	}
	for _, asset := range c.SetupAssets {
		if strings.EqualFold(asset.Name, "RUNNER.ZIP") {
			return nil
		}
	}
	return errors.New("runner is absent; a pinned RUNNER.ZIP asset is required before boot")
}

type Driver struct {
	Name        string            `json:"name"`
	INFVersions map[string]string `json:"inf_versions"`
}

// Manifest deliberately has no credential or private setup fields.
type Manifest struct {
	Topology         *winguest.Topology `json:"topology,omitempty"`
	BuildID          string             `json:"build_id"`
	GuestName        string             `json:"guest_name"`
	GuestUser        string             `json:"guest_user"`
	Source           string             `json:"source"`
	SourceSHA256     string             `json:"source_sha256"`
	Template         string             `json:"template,omitempty"`
	Output           string             `json:"output"`
	Size             int64              `json:"size"`
	SHA256           string             `json:"sha256"`
	ProbeSHA256      string             `json:"probe_sha256"`
	ValidationSHA256 string             `json:"validation_sha256"`
	AutologonSHA256  string             `json:"autologon_sha256"`
	Assets           map[string]string  `json:"assets"`
	RunnerVersion    string             `json:"runner_version,omitempty"`
	Drivers          []Driver           `json:"drivers"`
	Revision         string             `json:"vcs_revision"`
	Started          time.Time          `json:"started"`
	Ended            time.Time          `json:"ended"`
	PhaseMS          map[string]int64   `json:"phase_ms"`
}

// cleanupOwned makes absence the barrier before detaching or removing storage.
// Termination errors do not override a later authoritative absence observation.
func cleanupOwned(terminate func() error, absent func() error, detach func() error, remove func() error) error {
	if terminate != nil {
		_ = terminate()
	}
	if err := absent(); err != nil {
		return errors.Join(errors.New("build workspace retained: native absence unconfirmed"), err)
	}
	if err := detach(); err != nil {
		return errors.Join(errors.New("build workspace retained: disk detach unconfirmed"), err)
	}
	return remove()
}
