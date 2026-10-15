// Package hostinfo reports the host's CPU and memory for budget checks.
package hostinfo

import "runtime"

// Info is the host's hardware.
type Info struct {
	CPUs        int
	MemoryBytes uint64
}

// Get returns the host's CPU count and physical memory.
func Get() Info {
	return Info{CPUs: runtime.NumCPU(), MemoryBytes: memoryBytes()}
}
