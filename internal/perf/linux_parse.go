package perf

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
)

func parseLinux(stat, memory io.Reader) (counters, error) {
	var result counters
	lines := bufio.NewScanner(stat)
	for lines.Scan() {
		f := strings.Fields(lines.Text())
		if len(f) == 0 || !strings.HasPrefix(f[0], "cpu") || f[0] == "cpu" {
			continue
		}
		id, err := strconv.Atoi(strings.TrimPrefix(f[0], "cpu"))
		if err != nil || id != len(result.cpu) || len(result.cpu) >= maxCPUs || len(f) < 5 {
			return result, errors.New("invalid logical CPU counters")
		}
		var total, idle uint64
		// Guest/guest_nice are already counted in user/nice, so exclude them.
		for i := 1; i < min(len(f), 9); i++ {
			n, err := strconv.ParseUint(f[i], 10, 64)
			if err != nil || total+n < total {
				return result, errors.New("invalid logical CPU counters")
			}
			total += n
			if i == 4 || i == 5 {
				idle += n
			} // Idle plus I/O wait do not consume CPU.
		}
		result.cpu = append(result.cpu, cpuTime{busy: total - idle, total: total})
	}
	if lines.Err() != nil {
		return result, errors.New("CPU counter read failed")
	}
	lines = bufio.NewScanner(memory)
	totalFound, availableFound := false, false
	for lines.Scan() {
		f := strings.Fields(lines.Text())
		if len(f) != 3 || f[0] != "MemTotal:" && f[0] != "MemAvailable:" {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil || f[2] != "kB" || n > ^uint64(0)/1024 {
			return result, errors.New("invalid memory counters")
		}
		if f[0] == "MemTotal:" {
			result.total = n * 1024
			totalFound = true
		} else {
			result.available = n * 1024
			availableFound = true
		}
	}
	if lines.Err() != nil || !totalFound || !availableFound || result.total == 0 || result.available > result.total || len(result.cpu) == 0 {
		return result, errors.New("incomplete performance counters")
	}
	return result, nil
}
