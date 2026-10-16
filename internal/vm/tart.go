package vm

import (
	"encoding/json"
	"errors"
	"fmt"
)

// tartConfigFile is a Tart-format VM's description, read only on import.
const tartConfigFile = "config.json"

// tartConfig is the subset of Tart's config.json that importing needs.
type tartConfig struct {
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
	Display       struct {
		Width  int `json:"width"`
		Height int `json:"height"`
	} `json:"display"`
}

func parseTartConfig(data []byte) (tartConfig, error) {
	var c tartConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return tartConfig{}, fmt.Errorf("parse %s: %w", tartConfigFile, err)
	}
	if c.Version != 1 {
		return tartConfig{}, fmt.Errorf("unsupported Tart config version %d", c.Version)
	}
	return c, nil
}

// manifest converts c, with the guest contract the importer vouches for.
func (c tartConfig) manifest(guest Guest) (Manifest, error) {
	if c.MemorySize%(1<<20) != 0 || c.MemorySizeMin%(1<<20) != 0 {
		return Manifest{}, errors.New("the Tart config's memory is not a whole number of MiB")
	}
	m := Manifest{
		Version:      ManifestVersion,
		OS:           c.OS,
		Arch:         c.Arch,
		CPU:          c.CPUCount,
		CPUMin:       c.CPUCountMin,
		MemoryMiB:    c.MemorySize >> 20,
		MemoryMinMiB: c.MemorySizeMin >> 20,
		MAC:          c.MACAddress,
		Display:      Display{Width: c.Display.Width, Height: c.Display.Height},
		Guest:        guest,
	}
	if c.OS == "darwin" {
		m.MacOS = &MacOSPlatform{HardwareModel: c.HardwareModel, MachineID: c.ECID}
	}
	return m, m.validate()
}
