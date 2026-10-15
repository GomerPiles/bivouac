package vm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ebitengine/purego/objc"
	"golang.org/x/sys/unix"
)

// VZVirtualMachineState values.
const (
	stateStopped  = 0
	stateRunning  = 1
	stateError    = 3
	stateStarting = 4
	stateStopping = 7
)

// withDefaults fills unset fields from def, then from 1024x768 at 72 ppi.
func (d Display) withDefaults(def Display) Display {
	if d.Width == 0 {
		d.Width, d.Height = def.Width, def.Height
	}
	if d.Width == 0 {
		d.Width, d.Height = 1024, 768
	}
	if d.PPI == 0 {
		d.PPI = def.PPI
	}
	if d.PPI == 0 {
		d.PPI = 72
	}
	return d
}

// machineOptions select devices beyond the VM directory's own config.
type machineOptions struct {
	// share is a host directory exposed read-only as "bivouac" under the
	// macOS automount tag (/Volumes/My Shared Files/bivouac). Empty: none.
	share string
	// networkFD is a SOCK_DGRAM socket carrying the guest's Ethernet frames
	// (Softnet's peer), or -1 for the framework's shared NAT.
	networkFD int
	// input attaches a keyboard and pointing devices.
	input bool
	// display is the macOS graphics display, defaults applied.
	display Display
	// diskSync is a VZDiskImageSynchronizationMode.
	diskSync int
}

// machine is one VZVirtualMachine on its own serial queue.
type machine struct {
	f     *framework
	queue uintptr
	vm    objc.ID
}

func newMachine(f *framework, dir string, c Manifest, opts machineOptions) (*machine, error) {
	m := &machine{f: f, queue: f.queueCreate("dev.bivouac.vm", 0)}
	if m.queue == 0 {
		return nil, errors.New("create dispatch queue")
	}
	var err error
	f.onQueue(m.queue, func() {
		var config objc.ID
		config, err = buildConfiguration(f, dir, c, opts)
		if err != nil {
			return
		}
		var nsErr objc.ID
		if !objc.Send[bool](config, f.sel("validateWithError:"), errOut(&nsErr)) {
			err = fmt.Errorf("invalid VM configuration: %s", f.errorText(nsErr))
			return
		}
		m.vm, err = f.make("VZVirtualMachine", "initWithConfiguration:queue:", config, m.queue)
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

func buildConfiguration(f *framework, dir string, c Manifest, opts machineOptions) (objc.ID, error) {
	config, err := f.make("VZVirtualMachineConfiguration", "")
	if err != nil {
		return 0, err
	}
	f.send(config, "setCPUCount:", uint64(c.CPU)) //nolint:gosec // validate requires a positive count.
	f.send(config, "setMemorySize:", c.MemoryMiB<<20)

	caching := 0 // VZDiskImageCachingModeAutomatic
	if c.OS == "darwin" {
		if err := macPlatform(f, config, dir, c, opts.display); err != nil {
			return 0, err
		}
	} else {
		if err := linuxPlatform(f, config, dir); err != nil {
			return 0, err
		}
		caching = 2 // VZDiskImageCachingModeCached avoids Linux file system corruption
	}

	sync := opts.diskSync
	if sync == 0 {
		sync = syncFull
	}
	disk, err := f.makeErr("VZDiskImageStorageDeviceAttachment", "initWithURL:readOnly:cachingMode:synchronizationMode:error:",
		f.url(filepath.Join(dir, DiskFile)), false, caching, sync)
	if err != nil {
		return 0, err
	}
	block, err := f.make("VZVirtioBlockDeviceConfiguration", "initWithAttachment:", disk)
	if err != nil {
		return 0, err
	}
	f.send(config, "setStorageDevices:", f.array(block))

	nic, err := f.make("VZVirtioNetworkDeviceConfiguration", "")
	if err != nil {
		return 0, err
	}
	mac, err := f.make("VZMACAddress", "initWithString:", f.str(c.MAC))
	if err != nil {
		return 0, err
	}
	f.send(nic, "setMACAddress:", mac)
	var attachment objc.ID
	if opts.networkFD >= 0 {
		handle, err := f.make("NSFileHandle", "initWithFileDescriptor:closeOnDealloc:", int32(opts.networkFD), false) //nolint:gosec // A socketpair descriptor.
		if err != nil {
			return 0, err
		}
		attachment, err = f.make("VZFileHandleNetworkDeviceAttachment", "initWithFileHandle:", handle)
		if err != nil {
			return 0, err
		}
	} else if attachment, err = f.make("VZNATNetworkDeviceAttachment", ""); err != nil {
		return 0, err
	}
	f.send(nic, "setAttachment:", attachment)
	f.send(config, "setNetworkDevices:", f.array(nic))

	entropy, err := f.make("VZVirtioEntropyDeviceConfiguration", "")
	if err != nil {
		return 0, err
	}
	f.send(config, "setEntropyDevices:", f.array(entropy))
	balloon, err := f.make("VZVirtioTraditionalMemoryBalloonDeviceConfiguration", "")
	if err != nil {
		return 0, err
	}
	f.send(config, "setMemoryBalloonDevices:", f.array(balloon))
	vsock, err := f.make("VZVirtioSocketDeviceConfiguration", "")
	if err != nil {
		return 0, err
	}
	f.send(config, "setSocketDevices:", f.array(vsock))

	if opts.input {
		var keyboards, pointers []objc.ID
		for _, class := range []string{"VZUSBKeyboardConfiguration", "VZMacKeyboardConfiguration"} {
			if c.OS != "darwin" && class == "VZMacKeyboardConfiguration" {
				continue
			}
			k, err := f.make(class, "")
			if err != nil {
				return 0, err
			}
			keyboards = append(keyboards, k)
		}
		for _, class := range []string{"VZUSBScreenCoordinatePointingDeviceConfiguration", "VZMacTrackpadConfiguration"} {
			if c.OS != "darwin" && class == "VZMacTrackpadConfiguration" {
				continue
			}
			p, err := f.make(class, "")
			if err != nil {
				return 0, err
			}
			pointers = append(pointers, p)
		}
		f.send(config, "setKeyboards:", f.array(keyboards...))
		f.send(config, "setPointingDevices:", f.array(pointers...))
	}

	if opts.share != "" {
		shared, err := f.make("VZSharedDirectory", "initWithURL:readOnly:", f.url(opts.share), true)
		if err != nil {
			return 0, err
		}
		dirs := f.send(f.class("NSDictionary"), "dictionaryWithObject:forKey:", shared, f.str("bivouac"))
		share, err := f.make("VZMultipleDirectoryShare", "initWithDirectories:", dirs)
		if err != nil {
			return 0, err
		}
		tag := f.send(f.class("VZVirtioFileSystemDeviceConfiguration"), "macOSGuestAutomountTag")
		fsDevice, err := f.make("VZVirtioFileSystemDeviceConfiguration", "initWithTag:", tag)
		if err != nil {
			return 0, err
		}
		f.send(fsDevice, "setShare:", share)
		f.send(config, "setDirectorySharingDevices:", f.array(fsDevice))
	}
	return config, nil
}

// macPlatform keeps the graphics device even without a window, so the guest
// has a display and Metal for windowed tests.
func macPlatform(f *framework, config objc.ID, dir string, c Manifest, d Display) error {
	model, err := f.make("VZMacHardwareModel", "initWithDataRepresentation:", f.data(c.MacOS.HardwareModel))
	if err != nil {
		return err
	}
	if !objc.Send[bool](model, f.sel("isSupported")) {
		return errors.New("this host cannot run the baseline's macOS hardware model")
	}
	id, err := f.make("VZMacMachineIdentifier", "initWithDataRepresentation:", f.data(c.MacOS.MachineID))
	if err != nil {
		return err
	}
	aux, err := f.make("VZMacAuxiliaryStorage", "initWithURL:", f.url(filepath.Join(dir, NVRAMFile)))
	if err != nil {
		return err
	}
	platform, err := f.make("VZMacPlatformConfiguration", "")
	if err != nil {
		return err
	}
	f.send(platform, "setHardwareModel:", model)
	f.send(platform, "setMachineIdentifier:", id)
	f.send(platform, "setAuxiliaryStorage:", aux)
	f.send(config, "setPlatform:", platform)
	boot, err := f.make("VZMacOSBootLoader", "")
	if err != nil {
		return err
	}
	f.send(config, "setBootLoader:", boot)
	display, err := f.make("VZMacGraphicsDisplayConfiguration", "initWithWidthInPixels:heightInPixels:pixelsPerInch:", d.Width, d.Height, d.PPI)
	if err != nil {
		return err
	}
	graphics, err := f.make("VZMacGraphicsDeviceConfiguration", "")
	if err != nil {
		return err
	}
	f.send(graphics, "setDisplays:", f.array(display))
	f.send(config, "setGraphicsDevices:", f.array(graphics))
	return nil
}

func linuxPlatform(f *framework, config objc.ID, dir string) error {
	store, err := f.make("VZEFIVariableStore", "initWithURL:", f.url(filepath.Join(dir, NVRAMFile)))
	if err != nil {
		return err
	}
	boot, err := f.make("VZEFIBootLoader", "")
	if err != nil {
		return err
	}
	f.send(boot, "setVariableStore:", store)
	f.send(config, "setBootLoader:", boot)
	platform, err := f.make("VZGenericPlatformConfiguration", "")
	if err != nil {
		return err
	}
	f.send(config, "setPlatform:", platform)
	return nil
}

// completion waits for an NSError-only completion handler.
func (m *machine) completion(selector string) error {
	done := make(chan error, 1)
	block := objc.NewBlock(func(_ objc.Block, nsErr objc.ID) {
		if nsErr != 0 {
			done <- errors.New(m.f.errorText(nsErr))
			return
		}
		done <- nil
	})
	m.f.onQueue(m.queue, func() { m.f.send(m.vm, selector, block) })
	block.Release()
	return <-done
}

func (m *machine) start() error {
	if err := m.completion("startWithCompletionHandler:"); err != nil {
		return fmt.Errorf("start VM: %w", err)
	}
	return nil
}

// stop powers the VM off at once.
func (m *machine) stop() error { return m.completion("stopWithCompletionHandler:") }

func (m *machine) state() int {
	var s int
	m.f.onQueue(m.queue, func() { s = objc.Send[int](m.vm, m.f.sel("state")) })
	return s
}

// connect opens a stream to a guest vsock port. The returned file owns a
// duplicate descriptor; the framework's connection object is closed.
func (m *machine) connect(port uint32, timeout time.Duration) (*os.File, error) {
	type result struct {
		fd  int
		err error
	}
	done := make(chan result, 1)
	block := objc.NewBlock(func(_ objc.Block, conn, nsErr objc.ID) {
		if conn == 0 {
			done <- result{-1, errors.New(m.f.errorText(nsErr))}
			return
		}
		fd := objc.Send[int32](conn, m.f.sel("fileDescriptor"))
		dup, err := unix.Dup(int(fd))
		m.f.send(conn, "close")
		done <- result{dup, err}
	})
	m.f.onQueue(m.queue, func() {
		devices := m.f.send(m.vm, "socketDevices")
		device := m.f.send(devices, "firstObject")
		m.f.send(device, "connectToPort:completionHandler:", port, block)
	})
	block.Release()
	select {
	case r := <-done:
		if r.err != nil {
			return nil, r.err
		}
		unix.CloseOnExec(r.fd)
		if err := unix.SetNonblock(r.fd, true); err != nil {
			_ = unix.Close(r.fd)
			return nil, err
		}
		return os.NewFile(uintptr(r.fd), "vsock"), nil
	case <-time.After(timeout):
		// A late success is closed by the drain below.
		go func() {
			if r := <-done; r.err == nil {
				_ = unix.Close(r.fd)
			}
		}()
		return nil, errors.New("guest vsock connection timed out")
	}
}
