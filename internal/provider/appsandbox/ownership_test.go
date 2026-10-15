package appsandbox

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/provider"
)

func TestNativeNameRetainsFullID(t *testing.T) {
	for _, id := range []string{"00000000", "ffffffff", "00000001", "80000000", "12345678"} {
		name, err := NativeName(id)
		if err != nil || len(name) != 15 || !strings.HasPrefix(name, "bivouac-") {
			t.Fatalf("name for %s: %q, %v", id, name, err)
		}
		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(name[8:]))
		if err != nil || hex.EncodeToString(decoded) != id {
			t.Fatalf("ID was lost: %s -> %q", id, name)
		}
	}
	seen := make(map[string]bool)
	for i := range 10000 {
		name, err := NativeName(fmt.Sprintf("%08x", i))
		if err != nil || seen[name] {
			t.Fatalf("collision at %d", i)
		}
		seen[name] = true
	}
	for _, id := range []string{"", "1", "000000001", "FFFFFFFF", "g0000000", "../../vm"} {
		if _, err := NativeName(id); err == nil {
			t.Fatalf("accepted unsafe ID %q", id)
		}
	}
}

func cloneFixture(t *testing.T) (string, CloneRecord, VM) {
	t.Helper()
	root := t.TempDir()
	r, err := PlanClone(root, provider.Spec{
		Name: "bivouac-windows-12345678", Baseline: "generic-win11", CPU: 4, MemoryMB: 8192,
		Meta: provider.Metadata{ControllerID: "fixture-controller", InstanceID: "12345678", CreatedAt: "2026-01-01T00:00:00Z"},
	}, 80, 1)
	if err != nil {
		t.Fatal(err)
	}
	return root, r, VM{Name: r.NativeName, DiskDirectory: r.StorageParent, OSType: "Windows", CPUCores: 4, RAMMB: 8192, HDDGB: 80, GPUMode: 1}
}

func TestCloneOwnershipRequiresAllBindings(t *testing.T) {
	root, r, vm := cloneFixture(t)
	if err := CheckClone(root, r.Meta.ControllerID, r, r, r, vm); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*CloneRecord){
		func(r *CloneRecord) { r.Meta.ControllerID = "foreign-controller" },
		func(r *CloneRecord) { r.Meta.InstanceID = "87654321" },
		func(r *CloneRecord) { r.Meta.CreatedAt = "2026-01-02T00:00:00Z" },
		func(r *CloneRecord) { r.RunnerName = "bivouac-other-12345678" },
		func(r *CloneRecord) { r.NativeName = "bivouac-aaaaaaa" },
		func(r *CloneRecord) { r.StorageParent = filepath.Dir(r.StorageParent) },
		func(r *CloneRecord) { r.Template = "other-baseline" },
		func(r *CloneRecord) { r.CPU++ },
		func(r *CloneRecord) { r.MemoryMB++ },
		func(r *CloneRecord) { r.DiskGB++ },
		func(r *CloneRecord) { r.GPUMode = 0 },
	}
	for i, mutate := range mutations {
		changed := r
		mutate(&changed)
		for _, records := range [][3]CloneRecord{{changed, r, r}, {r, changed, r}, {r, r, changed}} {
			if err := CheckClone(root, r.Meta.ControllerID, records[0], records[1], records[2], vm); !errors.Is(err, provider.ErrNotOwned) {
				t.Fatalf("accepted changed binding %d: %v", i, err)
			}
		}
	}
	for _, records := range [][3]CloneRecord{{{}, r, r}, {r, {}, r}, {r, r, {}}} {
		if err := CheckClone(root, r.Meta.ControllerID, records[0], records[1], records[2], vm); !errors.Is(err, provider.ErrNotOwned) {
			t.Fatalf("accepted missing record: %v", err)
		}
	}
	// Matching markers copied elsewhere still cannot claim a different root.
	if err := CheckClone(t.TempDir(), r.Meta.ControllerID, r, r, r, vm); !errors.Is(err, provider.ErrNotOwned) {
		t.Fatal("accepted relocated storage")
	}
}

func TestCloneOwnershipRejectsChangedNativeMetadata(t *testing.T) {
	root, r, vm := cloneFixture(t)
	for _, mutate := range []func(*VM){
		func(v *VM) { v.Name = "foreign-vm" },
		func(v *VM) { v.DiskDirectory = filepath.Dir(v.DiskDirectory) },
		func(v *VM) { v.OSType = "Linux" },
		func(v *VM) { v.CPUCores++ },
		func(v *VM) { v.RAMMB++ },
		func(v *VM) { v.HDDGB++ },
		func(v *VM) { v.GPUMode = 0 },
		func(v *VM) { v.NetworkMode = 1 },
	} {
		changed := vm
		mutate(&changed)
		if err := CheckClone(root, r.Meta.ControllerID, r, r, r, changed); !errors.Is(err, provider.ErrNotOwned) {
			t.Fatalf("accepted changed native metadata: %v", err)
		}
	}
}

func TestPlanCloneRejectsUnsafeInputs(t *testing.T) {
	root, r, _ := cloneFixture(t)
	spec := provider.Spec{Name: r.RunnerName, Baseline: r.Template, CPU: r.CPU, MemoryMB: r.MemoryMB, Meta: r.Meta}
	for _, mutate := range []func(*provider.Spec){
		func(s *provider.Spec) { s.Name = "foreign-vm" },
		func(s *provider.Spec) { s.Baseline = r.NativeName },
		func(s *provider.Spec) { s.Baseline = "../baseline" },
		func(s *provider.Spec) { s.Meta.ControllerID = "" },
		func(s *provider.Spec) { s.Meta.CreatedAt = "invalid" },
		func(s *provider.Spec) { s.Meta.EngineName = "foreign-engine" },
		func(s *provider.Spec) { s.CPU = 0 },
		func(s *provider.Spec) { s.MemoryMB = 0 },
		func(s *provider.Spec) { s.Launch.Fields = map[string]string{"networkMode": "1"} },
		func(s *provider.Spec) { s.Launch.Args = []string{"override"} },
	} {
		changed := spec
		mutate(&changed)
		if _, err := PlanClone(root, changed, 80, 1); err == nil {
			t.Fatal("accepted unsafe intent")
		}
	}
	for _, path := range []string{"", ".", filepath.VolumeName(root) + string(filepath.Separator)} {
		if _, err := PlanClone(path, spec, 80, 1); err == nil {
			t.Fatalf("accepted storage root %q", path)
		}
	}
	if _, err := PlanClone(root, spec, 80, 2); err == nil {
		t.Fatal("accepted unvalidated GPU mode")
	}
}
