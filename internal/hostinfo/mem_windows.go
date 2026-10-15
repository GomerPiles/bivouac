package hostinfo

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func memoryBytes() uint64 {
	// MEMORYSTATUSEX has a fixed layout on both Windows architectures.
	var status struct {
		Length, Load                                                       uint32
		TotalPhysical, AvailablePhysical, TotalPageFile, AvailablePageFile uint64
		TotalVirtual, AvailableVirtual, AvailableExtended                  uint64
	}
	status.Length = uint32(unsafe.Sizeof(status))
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
	ok, _, _ := proc.Call(uintptr(unsafe.Pointer(&status))) // #nosec G103 -- Fixed-layout MEMORYSTATUSEX lives through this synchronous native call.
	if ok == 0 {
		return 0
	}
	return status.TotalPhysical
}
