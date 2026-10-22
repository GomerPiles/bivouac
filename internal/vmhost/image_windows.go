//go:build windows

package vmhost

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Missing, unprotected, malformed and legacy manifests all report contract 0.
// The serving host can read protected image directories; the manager cannot.
func imageContract(image string, check func(string) error) int {
	path := filepath.Join(filepath.Dir(image), "manifest.json")
	if check(filepath.Dir(image)) != nil || check(image) != nil || check(path) != nil {
		return 0
	}
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return 0
	}
	var manifest struct {
		WindowsContract int    `json:"windows_contract"`
		Output          string `json:"output"`
	}
	d := json.NewDecoder(io.LimitReader(f, 65537))
	if d.Decode(&manifest) != nil || d.Decode(new(any)) != io.EOF || !strings.EqualFold(manifest.Output, image) || manifest.WindowsContract < 1 {
		return 0
	}
	return manifest.WindowsContract
}
