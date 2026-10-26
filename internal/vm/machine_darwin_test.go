package vm

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/ebitengine/purego/objc"
	"golang.org/x/sys/unix"
)

// requireSigned is set by CI, which signs this test binary with the
// virtualization entitlement; elsewhere an unsigned binary skips.
const requireSigned = "BIVOUAC_VM_SIGNED_TESTS"

// genericHardwareModel is the data representation of Apple's generic macOS
// VM hardware model (platform 2, macOS 13 or later), as Tart records it.
const genericHardwareModel = "YnBsaXN0MDDTAQIDBAQFXxAZRGF0YVJlcHJlc2VudGF0aW9uVmVyc2lvbl8QD1BsYXRmb3JtVmVyc2lvbl8QEk1pbmltdW1TdXBwb3J0ZWRPUxACowYHBxANEAAIDys9UlRYWgAAAAAAAAEBAAAAAAAAAAgAAAAAAAAAAAAAAAAAAABc"

func signedFramework(t *testing.T) *framework {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckEntitlement(context.Background(), exe); err != nil {
		if os.Getenv(requireSigned) != "" {
			t.Fatal(err)
		}
		t.Skip("test binary is not signed with the virtualization entitlement")
	}
	f, err := openFramework()
	if err != nil {
		t.Fatal(err)
	}
	// A host that is itself a VM without nested virtualization (such as a
	// hosted CI runner) can still be unable to validate a configuration.
	if !objc.Send[bool](f.class("VZVirtualMachine"), f.sel("isSupported")) {
		t.Skip("this host does not support virtualization")
	}
	return f
}

// bytesOf copies an NSData.
func bytesOf(f *framework, data objc.ID) []byte {
	n := objc.Send[uint64](data, f.sel("length"))
	p := objc.Send[unsafe.Pointer](data, f.sel("bytes"))
	return append([]byte(nil), unsafe.Slice((*byte)(p), n)...) //nolint:gosec // NSData owns n bytes at p.
}

// TestConfigurationsValidate builds every device combination the helper
// can request and has the framework validate it, without booting. This is
// the check that the untyped bindings still match Virtualization.framework.
func TestConfigurationsValidate(t *testing.T) {
	f := signedFramework(t)
	queue := f.queueCreate("dev.bivouac.vm.test", 0)
	model, err := base64.StdEncoding.DecodeString(genericHardwareModel)
	if err != nil {
		t.Fatal(err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) })

	for _, guest := range []string{"darwin", "linux"} {
		t.Run(guest, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, DiskFile), make([]byte, 1<<20), 0o600); err != nil {
				t.Fatal(err)
			}
			c := Manifest{Version: ManifestVersion, OS: guest, Arch: "arm64", CPU: 2, MemoryMiB: 4096, MAC: "02:00:00:00:00:01", Guest: Guest{AgentVersion: 1}}
			var setupErr string
			f.onQueue(queue, func() {
				var nsErr objc.ID
				if guest == "linux" {
					if f.send(f.send(f.class("VZEFIVariableStore"), "alloc"), "initCreatingVariableStoreAtURL:options:error:", f.url(filepath.Join(dir, NVRAMFile)), uint64(0), errOut(&nsErr)) == 0 {
						setupErr = f.errorText(nsErr)
					}
					return
				}
				hw := f.send(f.send(f.class("VZMacHardwareModel"), "alloc"), "initWithDataRepresentation:", f.data(model))
				if hw == 0 || !objc.Send[bool](hw, f.sel("isSupported")) {
					setupErr = "unsupported macOS hardware model"
					return
				}
				c.MacOS = &MacOSPlatform{HardwareModel: model, MachineID: bytesOf(f, f.send(f.send(f.class("VZMacMachineIdentifier"), "new"), "dataRepresentation"))}
				if f.send(f.send(f.class("VZMacAuxiliaryStorage"), "alloc"), "initCreatingStorageAtURL:hardwareModel:options:error:", f.url(filepath.Join(dir, NVRAMFile)), hw, uint64(0), errOut(&nsErr)) == 0 {
					setupErr = f.errorText(nsErr)
				}
			})
			if setupErr != "" {
				t.Skipf("%s guest on this host: %s", guest, setupErr)
			}
			display := Display{}.withDefaults(c.Display)
			for _, opts := range []machineOptions{
				{networkFD: -1, display: display},
				{networkFD: -1, display: display, input: true, share: dir},
				{networkFD: fds[0], display: display},
				{networkFD: -1, display: Display{Width: 2560, Height: 1600, PPI: 144}, diskSync: syncNone},
				{networkFD: -1, display: display, diskSync: syncFsync},
			} {
				var buildErr error
				var valid bool
				var reason string
				f.onQueue(queue, func() {
					var config objc.ID
					config, buildErr = buildConfiguration(f, dir, c, opts)
					if buildErr != nil {
						return
					}
					var nsErr objc.ID
					valid = objc.Send[bool](config, f.sel("validateWithError:"), errOut(&nsErr))
					reason = f.errorText(nsErr)
				})
				if buildErr != nil {
					t.Errorf("%s %+v: %v", guest, opts, buildErr)
				} else if !valid {
					t.Errorf("%s %+v: %s", guest, opts, reason)
				}
			}
			if guest != "linux" {
				return
			}
			// Nesting validates where the host supports it and is refused,
			// before the framework sees it, everywhere else.
			var buildErr error
			var valid bool
			var reason string
			f.onQueue(queue, func() {
				var config objc.ID
				config, buildErr = buildConfiguration(f, dir, c, machineOptions{networkFD: -1, nested: true})
				if buildErr != nil {
					return
				}
				var nsErr objc.ID
				valid = objc.Send[bool](config, f.sel("validateWithError:"), errOut(&nsErr))
				reason = f.errorText(nsErr)
			})
			switch supported := f.nestedSupported(); {
			case supported && (buildErr != nil || !valid):
				t.Errorf("nested Linux guest on a supporting host: %v %s", buildErr, reason)
			case !supported && !errors.Is(buildErr, ErrNestedUnsupported):
				t.Errorf("nested Linux guest on a host without support: %v", buildErr)
			default:
				t.Logf("nested virtualization supported on this host: %v", supported)
			}
		})
	}
}

func TestAttachmentMTUGuardAndReadback(t *testing.T) {
	f, err := openFramework()
	if err != nil {
		t.Fatal(err)
	}
	// Default MTU does not even inspect a receiver, so older APIs remain valid.
	if err := f.setNetworkMTU(0, 1500); err != nil {
		t.Fatal(err)
	}
	dummy, err := f.make("NSObject", "")
	if err != nil {
		t.Fatal(err)
	}
	defer f.send(dummy, "release")
	if err := f.setNetworkMTU(dummy, 9000); err == nil {
		t.Fatal("missing MTU selector accepted")
	}
	fds, err := networkSocketpair(65535)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) }()
	handle, err := f.make("NSFileHandle", "initWithFileDescriptor:closeOnDealloc:", int32(fds[0]), false) //nolint:gosec // A socketpair FD.
	if err != nil {
		t.Fatal(err)
	}
	defer f.send(handle, "release")
	attachment, err := f.make("VZFileHandleNetworkDeviceAttachment", "initWithFileHandle:", handle)
	if err != nil {
		t.Fatal(err)
	}
	defer f.send(attachment, "release")
	if !objc.Send[bool](attachment, f.sel("respondsToSelector:"), f.sel("setMaximumTransmissionUnit:")) {
		t.Skip("MTU API unavailable; guard tested")
	}
	for _, mtu := range []int{9000, 65535} {
		if err := f.setNetworkMTU(attachment, mtu); err != nil {
			t.Fatal(err)
		}
	}
}
