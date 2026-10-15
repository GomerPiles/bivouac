// Package vm runs guests from Tart-format VM directories (config.json,
// disk.img, nvram.bin) in bivouac's own store with Apple's Virtualization
// framework. Running, cloning and stopping them needs only this package and
// a signed bivouac binary.
package vm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Files of a VM directory. Extra files, such as the provider's marker, are
// deleted with the VM.
const (
	ConfigFile = "config.json"
	DiskFile   = "disk.img"
	NVRAMFile  = "nvram.bin"
)

// runDir holds guest agent sockets, which exist only while a helper runs
// the VM. It is hidden, so no VM can be named after it.
const runDir = ".run"

// Entitlement is required of the executable that runs VMs.
const Entitlement = "com.apple.security.virtualization"

// maxSocketPath is sun_path's capacity on macOS, minus its terminator.
const maxSocketPath = 103

// ErrUnsupported reports a host without the Virtualization framework.
var ErrUnsupported = errors.New("guests from Tart-format VM directories require macOS on Apple Silicon")

// Config is the subset of Tart's config.json that running a VM needs.
// Writes go through updateConfig so fields Tart adds later survive.
type Config struct {
	Version       int    `json:"version"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	CPUCount      int    `json:"cpuCount"`
	CPUCountMin   int    `json:"cpuCountMin"`
	MemorySize    uint64 `json:"memorySize"`
	MemorySizeMin uint64 `json:"memorySizeMin"`
	MACAddress    string `json:"macAddress"`
	HardwareModel []byte `json:"hardwareModel"` // base64 VZMacHardwareModel
	ECID          []byte `json:"ecid"`          // base64 VZMacMachineIdentifier
	DiskFormat    string `json:"diskFormat"`
	Display       struct {
		Width  int `json:"width"`
		Height int `json:"height"`
	} `json:"display"`
}

// ReadConfig reads and validates dir's config.json.
func ReadConfig(dir string) (Config, error) {
	data, err := os.ReadFile(filepath.Join(dir, ConfigFile))
	if err != nil {
		return Config{}, err
	}
	return parseConfig(data)
}

func parseConfig(data []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", ConfigFile, err)
	}
	return c, c.validate()
}

func (c Config) validate() error {
	switch {
	case c.Version != 1:
		return fmt.Errorf("unsupported VM config version %d", c.Version)
	case c.Arch != "arm64":
		return fmt.Errorf("unsupported VM architecture %q", c.Arch)
	case c.OS != "darwin" && c.OS != "linux":
		return fmt.Errorf("unsupported VM OS %q", c.OS)
	case c.CPUCount < 1 || c.MemorySize == 0:
		return errors.New("VM config lacks CPU count or memory size")
	case c.OS == "darwin" && (len(c.HardwareModel) == 0 || len(c.ECID) == 0):
		return errors.New("macOS VM config lacks its hardware model or machine identifier")
	}
	if _, err := net.ParseMAC(c.MACAddress); err != nil {
		return errors.New("VM config has an invalid MAC address")
	}
	return nil
}

// updateConfig rewrites selected top-level fields of dir's config.json and
// keeps every other field as Tart wrote it.
func updateConfig(dir string, fields map[string]any) error {
	data, err := os.ReadFile(filepath.Join(dir, ConfigFile))
	if err != nil {
		return err
	}
	return rewriteConfig(dir, data, fields)
}

// rewriteConfig replaces dir's config.json with data plus fields, by rename.
func rewriteConfig(dir string, data []byte, fields map[string]any) error {
	path := filepath.Join(dir, ConfigFile)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse %s: %w", ConfigFile, err)
	}
	for k, v := range fields {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		raw[k] = b
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// randomMAC is a locally administered unicast address, as Tart assigns on
// clone so concurrent clones never share a DHCP lease.
func randomMAC() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[0] = b[0]&0xfc | 0x02
	return net.HardwareAddr(b).String(), nil
}

// Store is bivouac's VM store: each VM is the directory Store/<name>, and
// clones share blocks with their baseline because both live on its volume.
type Store string

// Dir is the VM directory for name.
func (s Store) Dir(name string) string { return filepath.Join(string(s), name) }

// SocketPath is where the helper serves name's guest agent connections. It
// is named by a hash of name, not by name, so its length does not depend on
// the VM or provider name; sun_path holds 103 bytes.
func (s Store) SocketPath(name string) (string, error) {
	sum := sha256.Sum256([]byte(name))
	p := filepath.Join(string(s), runDir, hex.EncodeToString(sum[:8])+".sock")
	if len(p) > maxSocketPath {
		return "", fmt.Errorf("guest agent socket path exceeds %d bytes; use a shorter VM store path", maxSocketPath)
	}
	return p, nil
}

// validName refuses names that could leave the store or are hidden.
func validName(name string) error {
	if name == "" || name == "." || name == ".." || strings.HasPrefix(name, ".") || strings.ContainsAny(name, "/\\\x00\n") {
		return fmt.Errorf("invalid VM name %q", name)
	}
	return nil
}

// Entry is one VM directory.
type Entry struct {
	Name    string
	Running bool
}
