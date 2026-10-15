package perf

import (
	"encoding/json"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestDarwinCounterInterpretationAndBounds(t *testing.T) {
	c, err := darwinCounters([]uint32{10, 20, 60, 10, 30, 40, 20, 10}, 1000*16384, 400, 16384)
	if err != nil || c.total != 16384000 || c.available != 6553600 || !reflect.DeepEqual(c.cpu, []cpuTime{{40, 100}, {80, 100}}) {
		t.Fatal(c, err)
	}
	for _, ticks := range [][]uint32{nil, {1}, make([]uint32, (maxCPUs+1)*4)} {
		if _, err := darwinCounters(ticks, 1000, 1, 1); err == nil {
			t.Fatal("invalid processor array admitted")
		}
	}
	for _, memory := range [][3]uint64{{0, 0, 4096}, {1000, 1, 0}, {1000, 2, 1000}, {1000, ^uint64(0), 4096}} {
		if _, err := darwinCounters([]uint32{1, 2, 3, 4}, memory[0], memory[1], memory[2]); err == nil {
			t.Fatal("invalid memory arithmetic admitted")
		}
	}
	c, err = darwinCounters([]uint32{^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0)}, 1000, 0, 1)
	if err != nil || c.cpu[0].total != uint64(^uint32(0))*4 {
		t.Fatal("tick addition overflowed", c, err)
	}
}

// Repeated native reads exercise the page-size guard and subsequent Go heap
// use. The old uint32 vm_size_t binding overwrote the adjacent guard on read 1.
func TestDarwinSamplingPreservesJSON(t *testing.T) {
	value := struct {
		Mode    string    `json:"mode"`
		Memory  uint64    `json:"memory"`
		Updated time.Time `json:"updated"`
	}{"on", 32 << 30, time.Now()}
	s := NewSampler(t.TempDir())
	for i := range 1000 {
		if _, err := s.Sample(); err != nil {
			t.Fatal(i, err)
		}
		if i%10 == 0 {
			runtime.GC()
		}
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil || !json.Valid(data) {
			t.Fatalf("sample %d corrupted JSON: %v", i, err)
		}
	}
}

func TestDarwinNativeSampler(t *testing.T) {
	s := NewSampler(t.TempDir())
	first, err := s.Sample()
	if err != nil || !first.valid() || first.CPUValid || first.Disk == nil || first.Commit != nil {
		t.Fatal("native macOS baseline unavailable", first, err)
	}
	time.Sleep(100 * time.Millisecond)
	next, err := s.Sample()
	if err != nil || !next.valid() || !next.CPUValid || len(next.CorePercent) != first.LogicalCPUs {
		t.Fatal("native macOS interval unavailable", next, err)
	}
	t.Log(next.String())
}
