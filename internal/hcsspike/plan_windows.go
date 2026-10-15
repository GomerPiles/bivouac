//go:build windows

// Package hcsspike is an offline Windows VM experiment. It is deliberately not
// registered with the CI manager and never talks to an App Sandbox daemon.
package hcsspike

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

const ownerPrefix = "bivouac-hcs-spike:"

// Config contains no credentials. Baseline is an independent, unenrolled image.
// A specialized image has the guest components already prepared; generalized
// templates require the explicit pinned SetupAssets for disposable provisioning.
type Config struct {
	Root           string        `json:"root"`
	InstanceID     string        `json:"instance_id"`
	Baseline       string        `json:"baseline"`
	BaselineSHA256 string        `json:"baseline_sha256"`
	GuestUser      string        `json:"guest_user"`
	CPU            int           `json:"cpu"`
	MemoryMB       int           `json:"memory_mb"`
	GPU            bool          `json:"gpu"`
	Drivers        []DriverShare `json:"drivers,omitempty"`
	TimeoutSeconds int           `json:"timeout_seconds"`
	SetupAssets    []SetupAsset  `json:"setup_assets,omitempty"`
	RenderProbe    *PinnedFile   `json:"render_probe,omitempty"`
}

// PinnedFile is a bounded public executable/resource, never a credential.
type PinnedFile struct {
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
}
type SetupAsset struct {
	Name string `json:"name"`
	PinnedFile
}

// DriverShare is copied to the owned trial directory before being shared. Only
// GPU driver payloads belong here, never personal directories or credentials.
// GuestPath follows the existing guest agent's driver-copy protocol.
type DriverShare struct {
	Source    string `json:"source"`
	GuestPath string `json:"guest_path"`
}

func DecodeConfig(r io.Reader) (Config, error) {
	var c Config
	b, err := io.ReadAll(io.LimitReader(r, 65537))
	if err != nil || len(b) > 65536 {
		return c, errors.New("spike configuration unreadable or exceeds 64 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, errors.New("invalid spike configuration")
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("spike configuration must contain one JSON object")
	}
	if len(c.Drivers) == 0 {
		c.Drivers = nil
	}
	if len(c.SetupAssets) == 0 {
		c.SetupAssets = nil
	}
	return c, c.Validate()
}

func localPath(path string) bool {
	if len(path) < 4 || path[1:3] != `:\` || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	if (path[0] < 'A' || path[0] > 'Z') && (path[0] < 'a' || path[0] > 'z') {
		return false
	}
	if strings.ContainsAny(path[3:], ":/\x00\r\n|\"<>?*") || strings.HasSuffix(path, `\`) {
		return false
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if strings.HasSuffix(part, " ") || strings.HasSuffix(part, ".") {
			return false
		}
		stem := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || (len(stem) == 4 && stem[3] >= '1' && stem[3] <= '9' && (stem[:3] == "COM" || stem[:3] == "LPT")) {
			return false
		}
	}
	return true
}

func within(parent, child string) bool {
	return strings.EqualFold(parent, child) || strings.HasPrefix(strings.ToLower(child), strings.ToLower(parent)+`\`)
}

func (c Config) Validate() error {
	id, err := hex.DecodeString(c.InstanceID)
	if err != nil || len(id) != 16 || strings.ToLower(c.InstanceID) != c.InstanceID {
		return errors.New("instance_id must be 32 lowercase hexadecimal characters")
	}
	if !localPath(c.Root) || !strings.EqualFold(filepath.Base(c.Root), "HCS-Spike") || !localPath(c.Baseline) || within(c.Root, c.Baseline) || !strings.EqualFold(filepath.Ext(c.Baseline), ".vhdx") {
		return errors.New("use a dedicated local HCS-Spike root and an external baseline VHDX")
	}
	hash, err := hex.DecodeString(c.BaselineSHA256)
	if err != nil || len(hash) != 32 {
		return errors.New("baseline_sha256 must pin the immutable image")
	}
	if len(c.GuestUser) < 1 || len(c.GuestUser) > 32 || strings.ContainsAny(c.GuestUser, "\x00\r\n\\/@ :\t") {
		return errors.New("guest_user must name a local guest account")
	}
	if c.CPU < 1 || c.CPU > 4 || c.MemoryMB < 1024 || c.MemoryMB > 8192 || c.MemoryMB%2 != 0 || c.TimeoutSeconds < 30 || c.TimeoutSeconds > 600 {
		return errors.New("spike bounds: 1-4 CPUs, 1024-8192 even MiB, 30-600 seconds")
	}
	if len(c.Drivers) > 16 || (!c.GPU && len(c.Drivers) != 0) {
		return errors.New("at most 16 driver shares, only with GPU enabled")
	}
	for _, driver := range c.Drivers {
		if !localPath(driver.Source) || within(c.Root, driver.Source) || within(driver.Source, c.Root) || !localPath(driver.GuestPath) || !strings.HasPrefix(strings.ToLower(driver.GuestPath), `c:\windows\hostdriverstore\filerepository\`) {
			return errors.New("driver sources must be external local directories; destinations must be under the guest HostDriverStore FileRepository")
		}
	}
	if err := validateAssets(c); err != nil {
		return err
	}
	return nil
}

func (c Config) name() string {
	id, _ := hex.DecodeString(c.InstanceID)
	return "bivouac-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id[:4]))
}

func (c Config) owner() string {
	rootID := sha256.Sum256([]byte(strings.ToLower(c.Root)))
	return ownerPrefix + hex.EncodeToString(rootID[:8]) + ":" + c.InstanceID
}
func (c Config) directory() string { return filepath.Join(c.Root, c.InstanceID) }
func (c Config) disk() string      { return filepath.Join(c.directory(), "disk.vhdx") }
func shareName(i int) string       { return fmt.Sprintf("AppSandbox.Drv.%d", i) }

// Plan returns typed JSON data only. It performs no filesystem or native calls.
// There is no NIC, host cache endpoint, clipboard, audio or display transport.
func Plan(c Config) (map[string]any, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	services := map[string]any{}
	for _, port := range []int{1, 7} {
		services[fmt.Sprintf("a5b0cafe-%04x-4000-8000-000000000001", port)] = map[string]any{
			"BindSecurityDescriptor":    "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
			"ConnectSecurityDescriptor": "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
			"AllowWildcardBinds":        false,
		}
	}
	devices := map[string]any{
		"Scsi":         map[string]any{"Primary": map[string]any{"Attachments": map[string]any{"0": map[string]string{"Type": "VirtualDisk", "Path": c.disk()}}}},
		"VideoMonitor": map[string]int{"HorizontalResolution": 1024, "VerticalResolution": 768},
		"HvSocket":     map[string]any{"HvSocketConfig": map[string]any{"ServiceTable": services}},
		"Keyboard":     struct{}{}, "Mouse": struct{}{},
	}
	if len(c.SetupAssets) != 0 {
		devices["Scsi"].(map[string]any)["Primary"].(map[string]any)["Attachments"].(map[string]any)["1"] = map[string]string{"Type": "Iso", "Path": filepath.Join(c.directory(), "setup-private", "setup.iso")}
	}
	if len(c.Drivers) != 0 {
		shares := []map[string]any{}
		for i := range c.Drivers {
			shares = append(shares, map[string]any{"Name": shareName(i), "AccessName": shareName(i), "Path": filepath.Join(c.directory(), "drivers", fmt.Sprint(i)), "Port": 50001, "Flags": 1})
		}
		devices["Plan9"] = map[string]any{"Shares": shares}
	}
	return map[string]any{
		"SchemaVersion": map[string]int{"Major": 2, "Minor": 1},
		"Owner":         c.owner(), "ShouldTerminateOnLastHandleClosed": true,
		"VirtualMachine": map[string]any{
			"Chipset":          map[string]any{"Uefi": map[string]string{"Console": "Default", "ApplySecureBootTemplate": "Apply", "SecureBootTemplateId": "1734c6e8-3154-4dda-ba5f-a874cc483422"}},
			"ComputeTopology":  map[string]any{"Memory": map[string]any{"SizeInMB": c.MemoryMB}, "Processor": map[string]int{"Count": c.CPU}},
			"Devices":          devices,
			"SecuritySettings": map[string]any{"EnableTpm": true, "Isolation": map[string]string{"IsolationType": "GuestStateOnly"}},
			"GuestState":       map[string]string{"GuestStateFilePath": filepath.Join(c.directory(), "vm.vmgs"), "RuntimeStateFilePath": filepath.Join(c.directory(), "vm.vmrs")},
		},
	}, nil
}

func gpuDocument() string {
	return `{"ResourcePath":"VirtualMachine/ComputeTopology/Gpu","RequestType":"Update","Settings":{"AssignmentMode":"Default","AllowVendorExtension":true}}`
}
