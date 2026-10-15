package crosvm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/appsandbox"
)

type Envelope struct {
	Options Options `json:"options"`
	Record  Record  `json:"record"`
}
type NativeState struct {
	Supervisor ProcessIdentity `json:"supervisor"`
	VM         ProcessIdentity `json:"vm"`
	Phase      string          `json:"phase"`
	Empty      bool            `json:"empty"`
	ExitCode   uint32          `json:"exit_code"`
	JobOwned   bool            `json:"job_owned"`
}

func readJSON(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 {
		return errors.New("native record exceeds bound or is unreadable")
	}
	if json.Unmarshal(data, out) != nil {
		return errors.New("invalid native ownership record")
	}
	return nil
}
func writeJSON(directory, name string, value any) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(name+".new", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return root.Rename(name+".new", name)
}
func inventory() ([]netip.Prefix, string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, "", err
	}
	var all []netip.Prefix
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, "", err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return nil, "", errors.New("invalid host interface inventory")
			}
			all = append(all, prefix)
		}
	}
	return denialInventory(all)
}

// Freeze effective IPv4 denial rather than interface identities. IPv6 is
// unconditionally dropped by the native packet filter. A new private adapter
// whose complete prefix is already denied cannot expand guest access; a new
// public prefix still changes the snapshot and retires the guest.
func denialInventory(all []netip.Prefix) ([]netip.Prefix, string, error) {
	blocked, _, err := appsandbox.BlockedPrefixes(all)
	if err != nil {
		return nil, "", err
	}
	prefixes := make([]netip.Prefix, len(blocked))
	for i, text := range blocked {
		prefixes[i], err = netip.ParsePrefix(text)
		if err != nil || !prefixes[i].Addr().Is4() || prefixes[i].Bits() == 0 {
			return nil, "", errors.New("invalid effective host denial")
		}
	}
	var effective []netip.Prefix
	var canonical []string
	for i, prefix := range prefixes {
		covered := false
		for j, outer := range prefixes {
			if i != j && outer.Bits() < prefix.Bits() && outer.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			effective = append(effective, prefix)
			canonical = append(canonical, prefix.String())
		}
	}
	if len(effective) == 0 || len(effective) > 128 {
		return nil, "", errors.New("effective host denial exceeds bound")
	}
	hash := sha256.Sum256([]byte(strings.Join(canonical, "\n")))
	return effective, hex.EncodeToString(hash[:]), nil
}

// Baseline admission is metadata-only. Images are operator-managed; lifecycle
// operations freeze their path and verify each overlay's backing metadata.
// Scanning a large raw image twice per guest dominated provisioning latency.
func rawBaselineSize(path string) (uint64, error) {
	file, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	size := file.Size()
	if !file.Mode().IsRegular() || size < 1 || size > 1<<40 {
		return 0, errors.New("invalid bounded raw baseline size")
	}
	return uint64(size), nil
}

func verifyLaunchInputs(o Options) error {
	_, err := rawBaselineSize(o.Baseline)
	return err
}

// Hash static tool inputs only during explicit operator prerequisite checks.
func verifySetupInputs(o Options) error {
	if _, err := rawBaselineSize(o.Baseline); err != nil {
		return err
	}
	for _, file := range []struct{ path, hash string }{{o.Binary, o.BinarySHA256}, {o.Kernel, o.KernelSHA256}, {o.Initrd, o.InitrdSHA256}} {
		if err := pinned(file.path, file.hash); err != nil {
			return err
		}
	}
	return nil
}

func pinned(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.New("pinned native input unavailable")
	}
	defer func() { _ = f.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return errors.New("read pinned native input")
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected) {
		return errors.New("pinned native input SHA-256 differs")
	}
	return nil
}

// loadEnvelope reads an envelope that must describe the directory at path.
func loadEnvelope(path string) (Envelope, error) {
	envelope, err := readEnvelope(path)
	if err == nil && filepath.Clean(path) != filepath.Join(envelope.Record.Directory, "owner.json") {
		err = provider.ErrNotOwned
	}
	return envelope, err
}

// readEnvelope validates an envelope and its independent marker. It does not
// compare path with the recorded directory, which may name the same directory
// in a non-canonical form; callers that read by another path must prove that.
func readEnvelope(path string) (Envelope, error) {
	var envelope Envelope
	if err := readJSON(path, &envelope); err != nil {
		return envelope, err
	}
	o, r := envelope.Options, envelope.Record
	if err := o.Validate(); err != nil {
		return envelope, err
	}
	if filepath.Clean(r.Directory) != filepath.Join(filepath.Clean(o.Root), r.Meta.InstanceID) {
		return envelope, provider.ErrNotOwned
	}
	if _, _, err := Launch(o, r); err != nil {
		return envelope, err
	}
	var marker Record
	if err := readJSON(filepath.Join(r.Directory, ".bivouac-owner.json"), &marker); err != nil || !Equal(marker, r) {
		return envelope, provider.ErrNotOwned
	}
	return envelope, nil
}
func verifyInventory(r Record) error {
	prefixes, snapshot, err := inventory()
	if err != nil || snapshot != r.HostSnapshot {
		return errors.New("host interfaces changed; retire the Linux guest")
	}
	canonical := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		canonical = append(canonical, prefix.Masked().String())
	}
	slices.Sort(canonical)
	canonical = slices.Compact(canonical)
	if !slices.Equal(canonical, r.HostPrefixes) {
		return errors.New("host denial snapshot differs")
	}
	return nil
}
