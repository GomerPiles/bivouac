package perf

import (
	"errors"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// Mach has no sysctl for per-processor ticks. Purego calls the system library
// without cgo; all bindings and Mach resources belong to this one read.
func readCounters() (counters, error) {
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return counters{}, errors.New("mach performance counters unavailable")
	}
	defer func() { _ = purego.Dlclose(lib) }()
	var hostSelf, taskSelf func() uint32
	var portDeallocate func(uint32, uint32) int32
	var processorInfo func(uint32, int32, *uint32, **[maxCPUs * 4]uint32, *uint32) int32
	var vmDeallocate func(uint32, *[maxCPUs * 4]uint32, uintptr) int32
	var statistics func(uint32, int32, *[38]uint32, *uint32) int32
	// host_page_size writes vm_size_t (uintptr_t), not natural_t (uint32).
	// A 32-bit output lets libSystem overwrite the next Go allocation.
	var pageSize func(uint32, *uintptr) int32
	for _, binding := range []struct {
		name     string
		function any
	}{
		{"mach_host_self", &hostSelf}, {"mach_task_self", &taskSelf},
		{"mach_port_deallocate", &portDeallocate}, {"host_processor_info", &processorInfo},
		{"vm_deallocate", &vmDeallocate}, {"host_statistics64", &statistics}, {"host_page_size", &pageSize},
	} {
		address, err := purego.Dlsym(lib, binding.name)
		if err != nil {
			return counters{}, errors.New("mach performance counters unavailable")
		}
		purego.RegisterFunc(binding.function, address)
	}
	host, task := hostSelf(), taskSelf()
	defer func() { _ = portDeallocate(task, host) }()
	var processors, cpuCount uint32
	var ticks *[maxCPUs * 4]uint32
	// PROCESSOR_CPU_LOAD_INFO allocates an out-of-line array of four natural_t
	// counters per logical processor, released even when its shape is rejected.
	if processorInfo(host, 2, &processors, &ticks, &cpuCount) != 0 {
		return counters{}, errors.New("logical CPU counters unavailable")
	}
	allocationBytes := uintptr(cpuCount) * 4
	defer func() { _ = vmDeallocate(task, ticks, allocationBytes) }()
	if processors == 0 || processors > maxCPUs || cpuCount != processors*4 || ticks == nil {
		return counters{}, errors.New("invalid logical CPU counters")
	}
	// HOST_VM_INFO64_REV1 is the stable 38-natural_t prefix. Later SDK fields
	// are unnecessary. Speculative pages are already included in free_count.
	var memory [38]uint32
	count := uint32(len(memory))
	// Keep an adjacent guard at the native boundary so a width regression is
	// detected without silently corrupting an unrelated allocation.
	page := struct {
		value uintptr
		guard uintptr
	}{guard: ^uintptr(0)}
	if statistics(host, 4, &memory, &count) != 0 || count != uint32(len(memory)) || pageSize(host, &page.value) != 0 || page.value == 0 {
		return counters{}, errors.New("physical memory counters unavailable")
	}
	if page.guard != ^uintptr(0) {
		return counters{}, errors.New("invalid native page-size result")
	}
	total, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return counters{}, errors.New("physical memory capacity unavailable")
	}
	return darwinCounters(ticks[:processors*4], total, uint64(memory[0])+uint64(memory[2]), uint64(page.value))
}

func darwinCounters(ticks []uint32, total, availablePages, pageSize uint64) (counters, error) {
	if len(ticks) == 0 || len(ticks)%4 != 0 || len(ticks)/4 > maxCPUs || pageSize == 0 || total == 0 || availablePages > total/pageSize {
		return counters{}, errors.New("invalid Mach performance counters")
	}
	c := counters{total: total, available: availablePages * pageSize}
	for i := 0; i < len(ticks); i += 4 {
		core := (*[4]uint32)(ticks[i : i+4])
		// CPU_STATE_USER, SYSTEM, IDLE, NICE. Widen before adding; native
		// 32-bit tick wrap invalidates one interval in the shared sampler.
		busy := uint64(core[0]) + uint64(core[1]) + uint64(core[3])
		c.cpu = append(c.cpu, cpuTime{busy: busy, total: busy + uint64(core[2])})
	}
	return c, nil
}
