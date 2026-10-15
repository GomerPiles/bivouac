// Package crosvm implements the Windows-hosted Linux/gfxstream provider.
// Native lifecycle activation remains gated on the isolated runtime tests.
package crosvm

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/provider"
)

const Policy = "public-ipv4-v1"
const gpuOptions = "backend=gfxstream,context-types=gfxstream-vulkan,gles=false,egl=false,vulkan=true,surfaceless=true,external-blob=true,system-blob=true,pci-bar-size=1073741824,displays=[[hidden=true,mode=windowed[800,600]]]"
const kernelOptions = "root=/dev/vda2 rw console=ttyS0,115200 net.ifnames=0 drm_kms_helper.fbdev_emulation=0"

// Options select pinned local tools and an immutable generic baseline.
// No arbitrary launch arguments, host shares, project setup or credentials.
type Options struct {
	Name         string `json:"name"`
	ControllerID string `json:"controller_id"`
	Root         string `json:"root"`
	Binary       string `json:"binary"`
	BinarySHA256 string `json:"binary_sha256"`
	QemuImg      string `json:"qemu_img"`
	BaselineName string `json:"baseline_name"`
	Baseline     string `json:"baseline"`
	Kernel       string `json:"kernel"`
	KernelSHA256 string `json:"kernel_sha256"`
	Initrd       string `json:"initrd"`
	InitrdSHA256 string `json:"initrd_sha256"`
	GPU          bool   `json:"gpu"`
}
type Record struct {
	Meta         provider.Metadata `json:"meta"`
	Name         string            `json:"name"`
	Directory    string            `json:"directory"`
	Disk         string            `json:"disk"`
	Binary       string            `json:"binary"`
	BinarySHA256 string            `json:"binary_sha256"`
	Baseline     string            `json:"baseline"`
	CPU          int               `json:"cpu"`
	MemoryMB     int               `json:"memory_mb"`
	GPU          bool              `json:"gpu"`
	SSHPort      int               `json:"ssh_port"`
	Policy       string            `json:"policy"`
	HostPrefixes []string          `json:"host_prefixes"`
	HostSnapshot string            `json:"host_snapshot"`
}

func identifier(value string, limit int) bool {
	if value == "" || len(value) > limit || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, char := range []byte(value) {
		valid := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-'
		if !valid {
			return false
		}
	}
	return true
}
func digest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func (o Options) Validate() error {
	if !identifier(o.Name, 31) || !identifier(o.ControllerID, 64) || !identifier(o.BaselineName, 63) ||
		strings.HasPrefix(o.BaselineName, "bivouac-") || !digest(o.BinarySHA256) || !digest(o.KernelSHA256) || !digest(o.InitrdSHA256) {
		return errors.New("invalid pinned Crosvm options")
	}
	for _, path := range []string{o.Root, o.Binary, o.QemuImg, o.Baseline, o.Kernel, o.Initrd} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n,") {
			return errors.New("crosvm requires absolute local paths without option separators")
		}
	}
	root := filepath.Clean(o.Root)
	if root == filepath.VolumeName(root)+string(filepath.Separator) || strings.HasPrefix(root, `\\`) {
		return errors.New("crosvm requires a dedicated local instance root")
	}
	for _, path := range []string{o.Binary, o.QemuImg, o.Baseline, o.Kernel, o.Initrd} {
		if strings.HasPrefix(strings.ToLower(filepath.Clean(path)), strings.ToLower(root)+string(filepath.Separator)) {
			return errors.New("crosvm tools and baseline must be outside disposable storage")
		}
	}
	return nil
}

// Canonical returns the options with every path cleaned and, where the file
// exists, resolved to its final path. On Windows that follows symlinks,
// junctions and mount points, expands short names and takes the stored case,
// as processImage does for running images, so recorded native images and overlay
// backing metadata compare with the frozen configuration. Missing files keep
// their cleaned absolute path; the root must already exist.
func (o Options) Canonical() (Options, error) {
	if err := o.Validate(); err != nil {
		return Options{}, err
	}
	for _, path := range []*string{&o.Root, &o.Binary, &o.QemuImg, &o.Baseline, &o.Kernel, &o.Initrd} {
		resolved, err := resolvePath(*path)
		switch {
		case err == nil:
			*path = filepath.Clean(resolved)
		case errors.Is(err, fs.ErrNotExist) && path != &o.Root:
			*path = filepath.Clean(*path)
		default:
			return Options{}, errors.New("cannot resolve configured Crosvm path")
		}
	}
	if _, err := os.Stat(o.Root); err != nil {
		return Options{}, err
	}
	return o, o.Validate()
}

// sameImage compares native image paths case-insensitively after the
// normalization applied by Canonical and processImage.
func sameImage(a, b string) bool {
	normalize := func(path string) string {
		path = strings.TrimPrefix(path, `\\?\`)
		return filepath.Clean(path)
	}
	return strings.EqualFold(normalize(a), normalize(b))
}

// compareIdentity reports whether a live process at the recorded PID is the
// recorded process. Another creation time proves the recorded one exited and
// the PID was reused. The same creation time with another image cannot be
// explained by reuse and remains an error.
func compareIdentity(expected, actual ProcessIdentity) (bool, error) {
	if expected.PID != actual.PID || expected.Created != actual.Created {
		return false, nil
	}
	if !sameImage(expected.Image, actual.Image) {
		return false, errors.New("native process image changed for the same PID and creation time")
	}
	return true, nil
}

// imageBase is the executable name of a recorded Windows image path.
func imageBase(path string) string {
	return path[strings.LastIndexAny(path, `\/`)+1:]
}

// Plan freezes resources, the baseline and host-interface snapshot before any
// disk or process operation. The caller must choose an unused loopback port.
func Plan(o Options, spec provider.Spec, port int, host []netip.Prefix, snapshot string) (Record, error) {
	if err := o.Validate(); err != nil {
		return Record{}, err
	}
	id := spec.Meta.InstanceID
	if len(id) != 8 || id != strings.ToLower(id) {
		return Record{}, errors.New("invalid Crosvm instance ID")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return Record{}, errors.New("invalid Crosvm instance ID")
	}
	if spec.Name != "bivouac-"+o.Name+"-"+id || spec.Baseline != o.BaselineName || spec.Meta.ControllerID != o.ControllerID ||
		spec.Meta.ParentName != "" || spec.Meta.EngineName != "" || spec.Meta.NetworkPolicy != "" || len(spec.Launch.Args) != 0 || len(spec.Launch.Fields) != 0 {
		return Record{}, provider.ErrNotOwned
	}
	if _, err := time.Parse(time.RFC3339Nano, spec.Meta.CreatedAt); err != nil {
		return Record{}, errors.New("invalid Crosvm creation time")
	}
	if spec.CPU < 1 || spec.CPU > 1024 || spec.MemoryMB < 512 || spec.MemoryMB > 1048576 || port < 1024 || port > 65535 || !digest(snapshot) || len(host) == 0 || len(host) > 128 {
		return Record{}, errors.New("invalid bounded Crosvm resources or host inventory")
	}
	prefixes := make([]string, 0, len(host))
	for _, prefix := range host {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() == 0 {
			return Record{}, errors.New("invalid host IPv4 prefix")
		}
		prefixes = append(prefixes, prefix.Masked().String())
	}
	slices.Sort(prefixes)
	prefixes = slices.Compact(prefixes)
	directory := filepath.Join(filepath.Clean(o.Root), id)
	meta := spec.Meta
	meta.NetworkPolicy = Policy
	return Record{Meta: meta, Name: spec.Name, Directory: directory, Disk: filepath.Join(directory, "disk.qcow2"), Binary: o.Binary, BinarySHA256: o.BinarySHA256,
		Baseline: o.Baseline, CPU: spec.CPU, MemoryMB: spec.MemoryMB, GPU: o.GPU, SSHPort: port, Policy: Policy, HostPrefixes: prefixes, HostSnapshot: snapshot}, nil
}
func Equal(a, b Record) bool {
	return reflect.DeepEqual(a, b)
}

// Launch validates the immutable record again; a caller cannot add shares,
// mount host paths, disable policy, expose ports, or override the GPU backend.
func Launch(o Options, r Record) (args []string, environment []string, err error) {
	prefixes := make([]netip.Prefix, 0, len(r.HostPrefixes))
	for _, text := range r.HostPrefixes {
		prefix, parseErr := netip.ParsePrefix(text)
		if parseErr != nil {
			return nil, nil, provider.ErrNotOwned
		}
		prefixes = append(prefixes, prefix)
	}
	meta := r.Meta
	meta.NetworkPolicy = ""
	want, err := Plan(o, provider.Spec{Name: r.Name, Baseline: o.BaselineName, CPU: r.CPU, MemoryMB: r.MemoryMB, Meta: meta}, r.SSHPort, prefixes, r.HostSnapshot)
	if err != nil || !Equal(want, r) {
		return nil, nil, provider.ErrNotOwned
	}
	args = []string{"--log-level", "error", "run-mp", "--hypervisor", "whpx", "--name", r.Name, "--cpus", "num-cores=" + strconv.Itoa(r.CPU), "--mem", "size=" + strconv.Itoa(r.MemoryMB),
		"--block", r.Disk, "--initrd", o.Initrd, "--serial", "type=file,path=" + filepath.Join(r.Directory, "serial.log") + ",num=1,console=true,stdin=false", "--params", kernelOptions}
	if r.GPU {
		args = append(args, "--gpu", gpuOptions)
	}
	args = append(args, o.Kernel)
	environment = []string{"CROSVM_SLIRP_SSH_PORT=" + strconv.Itoa(r.SSHPort), "BIVOUAC_SLIRP_POLICY=" + Policy, "BIVOUAC_SLIRP_HOST_PREFIXES=" + strings.Join(r.HostPrefixes, ",")}
	return args, environment, nil
}
