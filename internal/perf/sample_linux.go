package perf

import (
	"errors"
	"io"
	"os"
)

func readCounters() (counters, error) {
	stat, err := os.Open("/proc/stat")
	if err != nil {
		return counters{}, errors.New("logical CPU counters unavailable")
	}
	defer func() { _ = stat.Close() }()
	memory, err := os.Open("/proc/meminfo")
	if err != nil {
		return counters{}, errors.New("physical memory counters unavailable")
	}
	defer func() { _ = memory.Close() }()
	return parseLinux(io.LimitReader(stat, 128<<10), io.LimitReader(memory, 64<<10))
}
