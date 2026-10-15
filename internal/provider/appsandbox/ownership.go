package appsandbox

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/provider"
)

// NativeName preserves every bit of the controller's four-byte instance ID
// while fitting Windows' 15-character computer-name limit. The logical GitHub
// runner name remains separate; truncating it would make collisions possible.
func NativeName(instanceID string) (string, error) {
	if len(instanceID) != 8 || instanceID != strings.ToLower(instanceID) {
		return "", errors.New("appsandbox requires an eight-character lowercase hex instance ID")
	}
	id, err := hex.DecodeString(instanceID)
	if err != nil {
		return "", errors.New("invalid App Sandbox instance ID")
	}
	return "bivouac-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id)), nil
}

// CloneRecord is immutable creation intent, not native inventory. A future
// lifecycle adapter must persist it before POST /vms and place matching markers
// in the fresh storage parent and, after native creation, its VM child. No
// password, SSH credential, runner token, or JIT configuration belongs here.
type CloneRecord struct {
	Meta          provider.Metadata `json:"meta"`
	RunnerName    string            `json:"runner_name"`
	NativeName    string            `json:"native_name"`
	StorageParent string            `json:"storage_parent"`
	Template      string            `json:"template"`
	CPU           int               `json:"cpu"`
	MemoryMB      int               `json:"memory_mb"`
	DiskGB        int               `json:"disk_gb"`
	GPUMode       int               `json:"gpu_mode"`
}

// PlanClone derives one parent per instance under a caller-protected root.
// It creates no directory, starts no daemon or VM, and grants no networking.
// Native creation must use networkMode=0 because it auto-starts the guest.
func PlanClone(root string, spec provider.Spec, diskGB, gpuMode int) (CloneRecord, error) {
	name, err := NativeName(spec.Meta.InstanceID)
	if err != nil {
		return CloneRecord{}, err
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) == filepath.VolumeName(root)+string(filepath.Separator) {
		return CloneRecord{}, errors.New("appsandbox storage requires a dedicated absolute root")
	}
	if !identifier(spec.Meta.ControllerID, 64) || !strings.HasPrefix(spec.Name, "bivouac-") || !identifier(spec.Name, 63) ||
		!identifier(spec.Baseline, 15) || spec.Baseline == name || spec.CPU < 1 || spec.MemoryMB < 512 || diskGB < 16 ||
		(gpuMode != 0 && gpuMode != 1) || len(spec.Launch.Args) != 0 || len(spec.Launch.Fields) != 0 ||
		spec.Meta.EngineName != "" || spec.Meta.ParentName != "" {
		return CloneRecord{}, errors.New("invalid isolated App Sandbox clone intent")
	}
	if _, err := time.Parse(time.RFC3339Nano, spec.Meta.CreatedAt); err != nil {
		return CloneRecord{}, errors.New("invalid App Sandbox creation time")
	}
	return CloneRecord{
		Meta: spec.Meta, RunnerName: spec.Name, NativeName: name,
		StorageParent: filepath.Join(filepath.Clean(root), spec.Meta.InstanceID), Template: spec.Baseline,
		CPU: spec.CPU, MemoryMB: spec.MemoryMB, DiskGB: diskGB, GPUMode: gpuMode,
	}, nil
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

// CheckClone checks three independent ownership records against native VM
// metadata. The caller supplies a trusted durable record, markers read through
// a protected storage root, and a fresh API response. Missing or changed markers
// are never inferred from a name or disk path. This proves identity only:
// networkMode=0 does not rule out an externally attached NIC, and successful
// ownership checks do not authorize untrusted jobs or claim network isolation.
func CheckClone(root, controllerID string, record, parentMarker, childMarker CloneRecord, vm VM) error {
	if record.Meta.ControllerID != controllerID {
		return provider.ErrNotOwned
	}
	expected, err := PlanClone(root, provider.Spec{
		Name: record.RunnerName, Baseline: record.Template, CPU: record.CPU, MemoryMB: record.MemoryMB, Meta: record.Meta,
	}, record.DiskGB, record.GPUMode)
	if err != nil || expected != record || record != parentMarker || record != childMarker {
		return provider.ErrNotOwned
	}
	if vm.Name != record.NativeName || !strings.EqualFold(filepath.Clean(vm.DiskDirectory), record.StorageParent) ||
		vm.OSType != "Windows" || vm.CPUCores != record.CPU || vm.RAMMB != record.MemoryMB || vm.HDDGB != record.DiskGB ||
		vm.GPUMode != record.GPUMode || vm.NetworkMode != 0 {
		return provider.ErrNotOwned
	}
	return nil
}
