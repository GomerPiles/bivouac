package perf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDiskBlockArithmeticBoundsAndReservedSpace(t *testing.T) {
	for _, input := range [][3]uint64{{0, 0, 4096}, {100, 101, 4096}, {100, 20, 0}, {^uint64(0), 0, 4096}} {
		if _, err := diskFromBlocks(input[0], input[1], input[2]); err == nil {
			t.Fatal("invalid filesystem arithmetic accepted", input)
		}
	}
	d, err := diskFromBlocks(100, 20, 4096)
	if err != nil || d.TotalBytes != 409600 || d.AvailableBytes != 81920 {
		t.Fatal(d, err)
	}
	full, err := diskFromBlocks(100, 0, 4096)
	if err != nil || !full.valid() || full.AvailableBytes != 0 {
		t.Fatal("full filesystem treated as unavailable", full, err)
	}
}

func TestDiskFailuresDoNotLoseCPUAndMemory(t *testing.T) {
	s := &Sampler{read: func() (counters, error) { return counters{cpu: []cpuTime{{1, 10}}, total: 100, available: 50}, nil }}
	for _, reader := range []func() (DiskSpace, error){
		func() (DiskSpace, error) { return DiskSpace{}, errors.New("unavailable") },
		func() (DiskSpace, error) { return DiskSpace{100, 101}, nil },
	} {
		s.readDisk = reader
		sample, err := s.Sample()
		if err != nil || sample.Disk != nil || sample.TotalBytes != 100 {
			t.Fatal("disk failure lost core telemetry", sample, err)
		}
	}
}

func TestDiskMinimumTracksSuccessfulSamplesAndResetsCapacity(t *testing.T) {
	now := time.Now().UTC()
	r := Report{}
	s := Sample{At: now, TotalBytes: 1000, AvailableBytes: 600, LogicalCPUs: 1, Disk: &DiskSpace{1000, 800}}
	r.add(s)
	s.At = now.Add(time.Second)
	s.Disk = &DiskSpace{1000, 100}
	r.add(s)
	s.At = now.Add(2 * time.Second)
	s.Disk = nil
	r.add(s)
	if !r.valid() || r.Disk.Samples != 2 || r.Disk.MinimumAvailableBytes != 100 || r.Disk.Latest.AvailableBytes != 100 {
		t.Fatal("failed disk read fabricated headroom", r)
	}
	s.At = now.Add(3 * time.Second)
	s.Disk = &DiskSpace{2000, 900}
	r.add(s)
	if !r.valid() || r.Disk.Samples != 1 || r.Disk.MinimumAvailableBytes != 900 {
		t.Fatal("capacity change mixed disk windows", r)
	}
}

func TestDiskOutputBoundedNumericAndUnavailableHonest(t *testing.T) {
	directory := t.TempDir()
	now := time.Now().UTC()
	r := Report{Complete: true}
	r.add(Sample{At: now, TotalBytes: 1000, AvailableBytes: 600, LogicalCPUs: 1, Disk: &DiskSpace{8 << 30, 3 << 30}})
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.ReplaceAll(data, []byte(`"disk":{`), []byte(`"disk":{"path":"synthetic-private-directory",`))
	if err := os.WriteFile(filepath.Join(directory, FileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	PrintEnd(context.Background(), &out, directory)
	if strings.Contains(out.String(), "synthetic-private") || !strings.Contains(out.String(), "runner disk minimum available=3.00 GiB; latest=3.00/8.00 GiB available; samples=1") || strings.Count(out.String(), "\n") != 1 {
		t.Fatal(out.String())
	}
	r.Disk = nil
	r.Latest.Disk = nil
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := save(root, r); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	PrintEnd(context.Background(), &out, directory)
	if !strings.Contains(out.String(), "runner disk unavailable") {
		t.Fatal(out.String())
	}
	for _, disk := range []*DiskReport{
		{Latest: DiskSpace{100, 101}, Samples: 1},
		{Latest: DiskSpace{100, 80}, Samples: 2},
		{Latest: DiskSpace{100, 80}, Samples: 1, MinimumAvailableBytes: 81},
	} {
		r.Disk = disk
		if r.valid() {
			t.Fatal("invalid disk report admitted", disk)
		}
	}
}

func TestNativeDiskSpaceReadOnlyAndPrivateErrors(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("native counters unavailable")
	}
	directory := t.TempDir()
	d, err := readDiskSpace(directory)
	if err != nil || !d.valid() {
		t.Fatal(d, err)
	}
	if _, err := readDiskSpace(filepath.Join(directory, "missing-synthetic-directory")); err == nil || strings.Contains(err.Error(), directory) {
		t.Fatal("native disk error leaked path or accepted missing directory")
	}
}
