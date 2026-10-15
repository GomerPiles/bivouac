package perf

import (
	"errors"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func readCounters() (counters, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return counters{}, ErrUnsupported
	}
	// Load only absolute system paths and release this call's references. No
	// mutable global DLL cache or growing module-reference count is needed.
	kernel, err := windows.LoadDLL(filepath.Join(system, "kernel32.dll"))
	if err != nil {
		return counters{}, ErrUnsupported
	}
	defer func() { _ = kernel.Release() }()
	var memory struct {
		Length, Load                                                                                  uint32
		Total, Available, TotalPage, AvailablePage, TotalVirtual, AvailableVirtual, AvailableExtended uint64
	}
	memory.Length = uint32(unsafe.Sizeof(memory))
	memoryAPI, err := kernel.FindProc("GlobalMemoryStatusEx")
	if err != nil {
		return counters{}, ErrUnsupported
	}
	// #nosec G103 -- Fixed native MEMORYSTATUSEX buffer remains live for this synchronous read.
	ok, _, _ := memoryAPI.Call(uintptr(unsafe.Pointer(&memory)))
	if ok == 0 {
		return counters{}, errors.New("physical memory counters unavailable")
	}
	// Documented SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION layout, including
	// explicit trailing padding. Kernel time includes idle time.
	var processors [maxCPUs]struct {
		Idle, Kernel, User uint64
		Reserved           [2]uint64
		Count, Padding     uint32
	}
	var size uint32
	ntdll, err := windows.LoadDLL(filepath.Join(system, "ntdll.dll"))
	if err != nil {
		return counters{}, ErrUnsupported
	}
	defer func() { _ = ntdll.Release() }()
	api, err := ntdll.FindProc("NtQuerySystemInformation")
	if err != nil {
		return counters{}, ErrUnsupported
	}
	// #nosec G103 -- Fixed-size native CPU counter array and returned byte count; no process or credential data.
	status, _, _ := api.Call(uintptr(windows.SystemProcessorPerformanceInformation), uintptr(unsafe.Pointer(&processors[0])), unsafe.Sizeof(processors), uintptr(unsafe.Pointer(&size)))
	stride := uint32(unsafe.Sizeof(processors[0]))
	if status != 0 || size == 0 || size > uint32(unsafe.Sizeof(processors)) || size%stride != 0 {
		return counters{}, errors.New("logical CPU counters unavailable")
	}
	c := counters{total: memory.Total, available: memory.Available}
	c.commit = readWindowsCommit(kernel)
	for _, p := range processors[:size/stride] {
		total := p.Kernel + p.User
		if total < p.Kernel || p.Idle > total {
			return counters{}, errors.New("invalid logical CPU counters")
		}
		c.cpu = append(c.cpu, cpuTime{busy: total - p.Idle, total: total})
	}
	return c, nil
}

func readWindowsCommit(kernel *windows.DLL) *CommitSpace {
	// PERFORMANCE_INFORMATION uses native SIZE_T fields (Go's uintptr), including
	// the ABI padding following cb. This query requires no process handle or
	// privilege adjustment. Only system commit totals enter telemetry.
	var info struct {
		Size                                               uint32
		CommitTotal, CommitLimit, CommitPeak               uintptr
		PhysicalTotal, PhysicalAvailable, SystemCache      uintptr
		KernelTotal, KernelPaged, KernelNonpaged, PageSize uintptr
		HandleCount, ProcessCount, ThreadCount             uint32
	}
	info.Size = uint32(unsafe.Sizeof(info))
	api, err := kernel.FindProc("K32GetPerformanceInfo")
	if err != nil {
		return nil
	}
	// #nosec G103 -- Fixed documented PERFORMANCE_INFORMATION buffer remains live during this synchronous read-only query.
	ok, _, _ := api.Call(uintptr(unsafe.Pointer(&info)), uintptr(info.Size))
	if ok == 0 {
		return nil
	}
	commit, valid := commitFromPages(uint64(info.CommitTotal), uint64(info.CommitLimit), uint64(info.CommitPeak), uint64(info.PageSize))
	if !valid {
		return nil
	}
	return &commit
}
