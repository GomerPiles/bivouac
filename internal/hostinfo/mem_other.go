//go:build !darwin && !windows

package hostinfo

// memoryBytes is unknown until the Windows and Linux providers land; 0
// disables the memory budget check.
func memoryBytes() uint64 { return 0 }
