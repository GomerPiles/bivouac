// Package winrunner runs the official Actions runner inside a disposable
// Windows guest. Its fixed guest adapter (`bivouac guest windows <mode>`) and
// Go modes are shared by Windows-guest providers; each
// provider delivers them over its own authenticated transport.
//
// No instance value is interpolated into a script or command line: settings
// arrive as JSON in Config, and JIT bytes only on stdin.
package winrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

// Config is the per-instance guest configuration, delivered as JSON.
type Config struct {
	NativeName    string `json:"native_name"`
	RunnerName    string `json:"runner_name"`
	ControllerID  string `json:"controller_id"`
	User          string `json:"user"`
	RunnerDir     string `json:"runner_dir"`
	Address       string `json:"address"`
	Gateway       string `json:"gateway"`
	Prefix        int    `json:"prefix"`
	MAC           string `json:"mac"`
	Archive       bool   `json:"archive"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

// ValidRunnerDir restricts the runner to a dedicated directory on the guest's
// system drive, outside Windows.
func ValidRunnerDir(path string) bool {
	return len(path) > 3 && strings.EqualFold(path[:3], `C:\`) &&
		!strings.ContainsAny(path, "\x00\r\n") && !strings.Contains(path, "..") &&
		!strings.EqualFold(strings.TrimRight(path, `\`), `C:\Windows`) &&
		!strings.HasPrefix(strings.ToLower(path), `c:\windows\`)
}

func identifier(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, b := range []byte(value) {
		valid := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-'
		if !valid {
			return false
		}
	}
	return true
}

// instanceID returns the eight-hex-digit instance ID ending a managed
// runner name (bivouac-<provider>-<id>).
func instanceID(name string) (string, error) {
	if !strings.HasPrefix(name, "bivouac-") || !identifier(name, 63) {
		return "", errors.New("invalid managed runner name")
	}
	id := name[strings.LastIndexByte(name, '-')+1:]
	if len(id) != 8 || strings.Trim(id, "0123456789abcdef") != "" {
		return "", errors.New("invalid managed runner instance ID")
	}
	return id, nil
}

// VerifyArchive checks a runner package before it is sent to a guest.
func VerifyArchive(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.New("runner archive unavailable")
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 512<<20 {
		return errors.New("invalid bounded runner archive")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, 512<<20+1))
	if err != nil || n > 512<<20 || n != stat.Size() {
		return errors.New("read runner archive")
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected) {
		return errors.New("runner archive hash differs")
	}
	return nil
}
