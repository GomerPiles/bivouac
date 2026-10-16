package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// ManifestFile is bivouac's description of a VM, beside its disk and NVRAM.
// It is what bivouac boots from; Tart's config.json is read only on import.
const ManifestFile = "vm.json"

// ManifestVersion is the manifest format this bivouac reads and writes.
const ManifestVersion = 1

// Manifest describes one VM: its machine, and what bivouac may assume of
// the guest. A baseline's manifest is written on import; each clone gets a
// copy with its own MAC, CPU, and memory.
type Manifest struct {
	Version   int    `json:"version"`
	OS        string `json:"os"`   // darwin or linux
	Arch      string `json:"arch"` // arm64
	CPU       int    `json:"cpu"`
	CPUMin    int    `json:"cpu_min,omitempty"`
	MemoryMiB uint64 `json:"memory_mib"`
	// MemoryMinMiB is the least memory the guest OS supports.
	MemoryMinMiB uint64 `json:"memory_min_mib,omitempty"`
	MAC          string `json:"mac"`
	// Display is the default display; zero means 1024x768 at 72 ppi.
	Display Display `json:"display"`
	// MacOS identifies a macOS guest's platform; absent for Linux guests.
	MacOS *MacOSPlatform `json:"macos,omitempty"`
	Guest Guest          `json:"guest"`
}

// MacOSPlatform is a macOS VM's hardware model and machine identifier, as
// the framework's data representations.
type MacOSPlatform struct {
	HardwareModel []byte `json:"hardware_model"`
	MachineID     []byte `json:"machine_id"`
}

// Display is a graphics display size. Zero fields take the default.
type Display struct {
	Width  int `json:"width,omitempty"`
	Height int `json:"height,omitempty"`
	PPI    int `json:"ppi,omitempty"`
}

// Guest is the contract between the image and bivouac.
type Guest struct {
	// AgentVersion is the protocol version of the installed bivouac guest
	// agent; bivouac refuses an image whose version differs from its own.
	AgentVersion int `json:"agent_version"`
	// RunnerDir is the preinstalled GitHub Actions runner; empty for an
	// image that runs no runner (a container engine).
	RunnerDir string `json:"runner_dir,omitempty"`
	// Sudo reports passwordless sudo for the agent's user, which the release
	// proxy's trust setup needs.
	Sudo bool `json:"sudo,omitempty"`
}

// Validate checks a display override or default.
func (d Display) Validate() error {
	if (d.Width == 0) != (d.Height == 0) || d.Width < 0 || d.Height < 0 || d.Width > 16384 || d.Height > 16384 || d.PPI < 0 || d.PPI > 1000 {
		return fmt.Errorf("invalid display %dx%d at %d ppi", d.Width, d.Height, d.PPI)
	}
	return nil
}

func (m Manifest) validate() error {
	switch {
	case m.Version != ManifestVersion:
		return fmt.Errorf("unsupported VM manifest version %d", m.Version)
	case m.Arch != "arm64":
		return fmt.Errorf("unsupported VM architecture %q", m.Arch)
	case m.OS != "darwin" && m.OS != "linux":
		return fmt.Errorf("unsupported VM OS %q", m.OS)
	case m.CPU < 1 || m.CPU < m.CPUMin || m.CPUMin < 0:
		return errors.New("VM manifest has an invalid CPU count")
	case m.MemoryMiB < 1 || m.MemoryMiB < m.MemoryMinMiB:
		return errors.New("VM manifest has an invalid memory size")
	case m.OS == "darwin" && (m.MacOS == nil || len(m.MacOS.HardwareModel) == 0 || len(m.MacOS.MachineID) == 0):
		return errors.New("macOS VM manifest lacks its hardware model or machine identifier")
	case m.OS == "linux" && m.MacOS != nil:
		return errors.New("a Linux VM manifest has a macOS platform")
	case m.Guest.AgentVersion < 1:
		return errors.New("VM manifest lacks the guest agent version")
	case m.Guest.RunnerDir != "" && (m.Guest.RunnerDir[0] != '/' || bytes.ContainsAny([]byte(m.Guest.RunnerDir), "\x00\n")):
		return errors.New("VM manifest runner_dir must be an absolute guest path")
	}
	if mac, err := net.ParseMAC(m.MAC); err != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return errors.New("VM manifest has an invalid MAC address")
	}
	return m.Display.Validate()
}

// ReadManifest reads and validates dir's manifest. A directory without one
// is not a bivouac VM: fs.ErrNotExist.
func ReadManifest(dir string) (Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return Manifest{}, err
	}
	return parseManifest(data)
}

func parseManifest(data []byte) (Manifest, error) {
	var m Manifest
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("parse %s: %w", ManifestFile, err)
	}
	return m, m.validate()
}

// writeManifest writes m into dir, which is not yet in place.
func writeManifest(dir string, m Manifest) error {
	if err := m.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ManifestFile), append(data, '\n'), 0o600)
}
