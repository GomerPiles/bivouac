package perf

import (
	"strings"
	"testing"
)

func TestLinuxCountersExcludeGuestDoubleCountAndIOWait(t *testing.T) {
	c, err := parseLinux(strings.NewReader("cpu 10 0 20 30 5 2 3 4 9 1\ncpu0 10 0 20 30 5 2 3 4 9 1\n"), strings.NewReader("MemTotal: 1000 kB\nMemAvailable: 600 kB\n"))
	if err != nil || len(c.cpu) != 1 || c.cpu[0].total != 74 || c.cpu[0].busy != 39 || c.total != 1024000 || c.available != 614400 {
		t.Fatal(c, err)
	}
	for _, memory := range []string{"MemTotal: 100 kB\n", "MemTotal: 100 kB\nMemAvailable: 101 kB\n", "MemTotal: 100 kB\nMemAvailable: 10 bytes\n"} {
		if _, err := parseLinux(strings.NewReader("cpu0 1 2 3 4\n"), strings.NewReader(memory)); err == nil {
			t.Fatal("invalid memory accepted")
		}
	}
}
