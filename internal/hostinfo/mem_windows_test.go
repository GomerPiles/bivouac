package hostinfo

import "testing"

func TestWindowsPhysicalMemory(t *testing.T) {
	if Get().MemoryBytes == 0 {
		t.Fatal("Windows memory budget cannot use an unknown physical-memory size")
	}
}
