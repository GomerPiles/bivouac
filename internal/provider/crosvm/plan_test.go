package crosvm

import (
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/provider"
)

func fixture(t *testing.T) (Options, Record) {
	t.Helper()
	base := t.TempDir()
	hash := strings.Repeat("a", 64)
	o := Options{Name: "linux", ControllerID: "test-controller", Root: filepath.Join(base, "instances"), Binary: filepath.Join(base, "tools", "crosvm.exe"), QemuImg: filepath.Join(base, "tools", "qemu-img.exe"),
		BinarySHA256: hash, BaselineName: "ci-linux", Baseline: filepath.Join(base, "baseline.raw"), Kernel: filepath.Join(base, "vmlinuz"), KernelSHA256: hash, Initrd: filepath.Join(base, "initrd"), InitrdSHA256: hash, GPU: true}
	return o, recordFor(t, o, "1234abcd")
}

func recordFor(t *testing.T, o Options, id string) Record {
	t.Helper()
	r, err := Plan(o, provider.Spec{Name: "bivouac-linux-" + id, Baseline: o.BaselineName, CPU: 4, MemoryMB: 4096, Meta: provider.Metadata{ControllerID: o.ControllerID, InstanceID: id, CreatedAt: "2026-01-01T00:00:00Z"}},
		24533, []netip.Prefix{netip.MustParsePrefix("192.168.1.7/24"), netip.MustParsePrefix("8.8.8.10/24")}, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestLaunchHasOnlyOwnedDiskAndMandatoryPublicPolicy(t *testing.T) {
	o, r := fixture(t)
	args, environment, err := Launch(o, r)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, r.Disk) || !slices.Contains(args, gpuOptions) || !slices.Contains(environment, "BIVOUAC_SLIRP_POLICY="+Policy) {
		t.Fatal("missing fixed isolation/GPU fields")
	}
	for _, argument := range args {
		if strings.HasPrefix(argument, "--dir") || strings.HasPrefix(argument, "--shared-dir") || strings.HasPrefix(argument, "--disable-sandbox") || strings.HasPrefix(argument, "--vsock") {
			t.Fatal("host exposure in fixed plan")
		}
	}
	if !slices.Contains(environment, "BIVOUAC_SLIRP_HOST_PREFIXES=192.168.1.0/24,8.8.8.0/24") {
		t.Fatal("host public/private networks missing")
	}
}
func TestLaunchRejectsRecordMutation(t *testing.T) {
	for _, field := range []string{"disk", "baseline", "binary", "controller", "policy", "name", "prefixes"} {
		t.Run(field, func(t *testing.T) {
			o, r := fixture(t)
			switch field {
			case "disk":
				r.Disk = filepath.Join(o.Root, "foreign.qcow2")
			case "baseline":
				r.Baseline = o.Kernel
			case "binary":
				r.Binary = o.QemuImg
			case "controller":
				r.Meta.ControllerID = "other"
			case "policy":
				r.Policy = ""
			case "name":
				r.Name = "foreign-vm"
			case "prefixes":
				r.HostPrefixes = []string{"0.0.0.0/0"}
			}
			if _, _, err := Launch(o, r); !errors.Is(err, provider.ErrNotOwned) {
				t.Fatal("changed native intent accepted")
			}
		})
	}
}
func TestToolsAndBaselineCannotLiveInDisposableRoot(t *testing.T) {
	o, _ := fixture(t)
	o.Baseline = filepath.Join(o.Root, "baseline.raw")
	if o.Validate() == nil {
		t.Fatal("baseline in disposable root accepted")
	}
}
