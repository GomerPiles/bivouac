//go:build windows

package winrunner

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type gpuCOM struct{ methods *[16]uintptr }
type gpuDescription struct {
	Description                                   [128]uint16
	VendorID, DeviceID, SubSysID, Revision        uint32
	DedicatedVideo, DedicatedSystem, SharedSystem uintptr
	LUID                                          windows.LUID
	Flags                                         uint32
}

func releaseGPU(object *gpuCOM) {
	if object != nil {
		// #nosec G103 -- The factory/device returned an IUnknown pointer; Release is slot 2.
		_, _, _ = syscall.SyscallN(object.methods[2], uintptr(unsafe.Pointer(object)))
	}
}

// hardwareD3D12 excludes WARP and proves that a physical adapter can create a
// D3D12 device in the runner's own interactive session. No display output or
// vendor names are accepted as a substitute for hardware device creation.
func hardwareD3D12() error {
	dxgi := windows.NewLazySystemDLL("dxgi.dll").NewProc("CreateDXGIFactory1")
	d3d := windows.NewLazySystemDLL("d3d12.dll").NewProc("D3D12CreateDevice")
	if dxgi.Find() != nil || d3d.Find() != nil {
		return errors.New("hardware D3D12 APIs unavailable")
	}
	factoryID, err := windows.GUIDFromString("{770aae78-f26f-4dba-a829-253c83d1b387}")
	if err != nil {
		return err
	}
	deviceID, err := windows.GUIDFromString("{189819f1-1db6-4b57-be54-1821339b85f7}")
	if err != nil {
		return err
	}
	var factory *gpuCOM
	// #nosec G103 -- Documented GUID input and COM interface-pointer output.
	status, _, _ := dxgi.Call(uintptr(unsafe.Pointer(&factoryID)), uintptr(unsafe.Pointer(&factory)))
	if status != 0 || factory == nil {
		return errors.New("hardware DXGI factory unavailable")
	}
	defer releaseGPU(factory)
	for index := uintptr(0); index < 32; index++ {
		var adapter *gpuCOM
		// #nosec G103 -- IDXGIFactory1::EnumAdapters1 is slot 12; output is released below.
		status, _, _ = syscall.SyscallN(factory.methods[12], uintptr(unsafe.Pointer(factory)), index, uintptr(unsafe.Pointer(&adapter)))
		if status == 0x887a0002 {
			break
		}
		if status != 0 || adapter == nil {
			return errors.New("hardware DXGI enumeration failed")
		}
		var description gpuDescription
		// #nosec G103 -- IDXGIAdapter1::GetDesc1 is slot 10 with a fixed native output structure.
		status, _, _ = syscall.SyscallN(adapter.methods[10], uintptr(unsafe.Pointer(adapter)), uintptr(unsafe.Pointer(&description)))
		if status == 0 && description.Flags&2 == 0 {
			var device *gpuCOM
			// #nosec G103 -- Documented D3D12CreateDevice ABI, minimum feature level 11.0.
			created, _, _ := d3d.Call(uintptr(unsafe.Pointer(adapter)), 0xb000, uintptr(unsafe.Pointer(&deviceID)), uintptr(unsafe.Pointer(&device)))
			releaseGPU(device)
			releaseGPU(adapter)
			if created == 0 && device != nil {
				return nil
			}
			continue
		}
		releaseGPU(adapter)
	}
	return errors.New("hardware D3D12 device unavailable; runner registration refused")
}
