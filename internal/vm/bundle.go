// Package vm runs guests from bivouac's own VM store with Apple's
// Virtualization framework. Each VM is a directory with a manifest (vm.json),
// a disk image, and NVRAM; Tart-format VMs are imported into that form.
// Running, cloning and stopping them needs only this package and a signed
// bivouac binary.
package vm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

// Image files of a VM directory, beside ManifestFile. Extra files, such as
// the provider's marker, are deleted with the VM.
const (
	DiskFile  = "disk.img"
	NVRAMFile = "nvram.bin"
)

// runDir holds guest agent sockets, which exist only while a helper runs
// the VM. It is hidden, so no VM can be named after it.
const runDir = ".run"

// Entitlement is required of the executable that runs VMs.
const Entitlement = "com.apple.security.virtualization"

// maxSocketPath is sun_path's capacity on macOS, minus its terminator.
const maxSocketPath = 103

// ErrUnsupported reports a host without the Virtualization framework.
var ErrUnsupported = errors.New("bivouac VMs require macOS on Apple Silicon")

// randomMAC is a locally administered unicast address, assigned on every
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
		return "", fmt.Errorf("guest agent socket path under %s exceeds %d bytes; use a shorter VM store path or BIVOUAC_HOME", string(s), maxSocketPath)
	}
	return p, nil
}

// CheckSocketPath fails when this store's guest agent sockets cannot fit
// sun_path. Their length depends only on the store path, so one check covers
// every VM before any guest starts.
func (s Store) CheckSocketPath() error {
	_, err := s.SocketPath("")
	return err
}

// validName refuses names that could leave the store or are hidden.
func validName(name string) error {
	if name == "" || name == "." || name == ".." || strings.HasPrefix(name, ".") || strings.ContainsAny(name, "/\\\x00\n") {
		return fmt.Errorf("invalid VM name %q", name)
	}
	return nil
}

// CloneOptions size a clone; zero keeps the baseline's value.
type CloneOptions struct {
	CPU       int
	MemoryMiB int
}

// Entry is one VM directory.
type Entry struct {
	Name    string
	Running bool
}
