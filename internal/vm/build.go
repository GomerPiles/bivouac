package vm

import (
	"encoding/hex"
	"errors"
	"net/url"
	"strings"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

// Build records public factory provenance. Imported images have no build section.
type Build struct {
	Recipe       string `json:"recipe"`
	SourceURL    string `json:"source_url"`
	SourceSHA256 string `json:"source_sha256"`
	RunnerURL    string `json:"runner_url"`
	RunnerSHA256 string `json:"runner_sha256"`
	HelperSHA256 string `json:"helper_sha256"`
	HostSHA256   string `json:"host_sha256"`
	DiskBytes    int64  `json:"disk_bytes"`
}

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && s == strings.ToLower(s)
}
func provenanceURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && len(s) <= 2048 && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !strings.ContainsAny(s, "\x00\r\n")
}
func (b Build) validate(m Manifest) error {
	// Historical pins and guest protocol versions remain readable. Only new
	// baseline admission compares their values with this executable's registry.
	if b.Recipe == "" || len(b.Recipe) > 100 || strings.ContainsFunc(b.Recipe, func(c rune) bool { return !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789.-", c) }) ||
		!provenanceURL(b.SourceURL) || !provenanceURL(b.RunnerURL) || !validDigest(b.SourceSHA256) || !validDigest(b.RunnerSHA256) || !validDigest(b.HelperSHA256) || !validDigest(b.HostSHA256) || b.DiskBytes < 16*vzrecipe.GiB || b.DiskBytes > 512*vzrecipe.GiB || b.DiskBytes%vzrecipe.GiB != 0 || m.OS != "linux" {
		return errors.New("invalid Linux baseline build provenance")
	}
	return nil
}

// NewLinuxManifest constructs a factory candidate's exact guest contract.
func NewLinuxManifest(cpu, memoryGB int) (Manifest, error) {
	if cpu < 1 || cpu > 1024 || memoryGB < 1 || memoryGB > 1024 {
		return Manifest{}, errors.New("invalid factory CPU or memory size")
	}
	mac, err := randomMAC()
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{Version: ManifestVersion, OS: "linux", Arch: "arm64", CPU: cpu, MemoryMiB: uint64(memoryGB) * 1024, MAC: mac, Guest: Guest{AgentVersion: guestagent.Version, RunnerDir: "/opt/actions-runner"}}
	return m, m.validate()
}
