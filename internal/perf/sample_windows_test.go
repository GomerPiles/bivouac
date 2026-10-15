package perf

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsReadOnlyNativeCounters(t *testing.T) {
	c, err := readCounters()
	if err != nil || c.total == 0 || c.available > c.total || len(c.cpu) < 1 || len(c.cpu) > maxCPUs {
		t.Fatal(c, err)
	}
	for _, cpu := range c.cpu {
		if cpu.total == 0 || cpu.busy > cpu.total {
			t.Fatal(cpu)
		}
	}
}

func TestWindowsReportReaderAllowsAtomicReplacement(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	r := Report{}
	r.add(Sample{At: time.Now().UTC(), TotalBytes: 1000, AvailableBytes: 600, LogicalCPUs: 1})
	if err := save(root, r); err != nil {
		t.Fatal(err)
	}
	old, err := openReport(filepath.Join(directory, FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = old.Close() }()
	r.add(Sample{At: time.Now().UTC(), TotalBytes: 1000, AvailableBytes: 200, LogicalCPUs: 1})
	if err := save(root, r); err != nil {
		t.Fatal("reader blocked atomic report replacement", err)
	}
	data, err := io.ReadAll(old)
	if err != nil {
		t.Fatal(err)
	}
	var prior Report
	if json.Unmarshal(data, &prior) != nil || prior.Latest.AvailableBytes != 600 {
		t.Fatal("old snapshot changed")
	}
	current, err := ReadReport(directory)
	if err != nil || current.Latest.AvailableBytes != 200 {
		t.Fatal(current, err)
	}
}
