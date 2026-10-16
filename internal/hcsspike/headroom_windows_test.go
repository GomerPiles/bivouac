//go:build windows

package hcsspike

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/perf"
)

func headroomSample() perf.Sample {
	return perf.Sample{TotalBytes: 32 << 30, AvailableBytes: 10 << 30, LogicalCPUs: 8, Commit: &perf.CommitSpace{LimitBytes: 40 << 30, UsedBytes: 34 << 30, PeakSinceBootBytes: 34 << 30}, Disk: &perf.DiskSpace{TotalBytes: 100 << 30, AvailableBytes: 8 << 30}}
}

func TestHeadroomRefusesPressureAndMissingCounters(t *testing.T) {
	c := exampleConfig()
	c.MemoryMB = 4096
	for _, test := range []struct {
		name    string
		mutate  func(*perf.Sample)
		invalid bool
	}{
		{"exact-boundary", func(*perf.Sample) {}, false},
		{"physical-pressure", func(s *perf.Sample) { s.AvailableBytes-- }, false},
		{"commit-pressure", func(s *perf.Sample) { s.Commit.UsedBytes++ }, false},
		{"disk-pressure", func(s *perf.Sample) { s.Disk.AvailableBytes-- }, false},
		{"cpu-pressure", func(s *perf.Sample) { s.LogicalCPUs = c.CPU + 1 }, false},
		{"missing-commit", func(s *perf.Sample) { s.Commit = nil }, true},
		{"missing-disk", func(s *perf.Sample) { s.Disk = nil }, true},
		{"invalid-commit", func(s *perf.Sample) { s.Commit.UsedBytes = s.Commit.LimitBytes + 1 }, true},
		{"invalid-physical", func(s *perf.Sample) { s.AvailableBytes = s.TotalBytes + 1 }, true},
		{"invalid-disk", func(s *perf.Sample) { s.Disk.AvailableBytes = s.Disk.TotalBytes + 1 }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sample := headroomSample()
			test.mutate(&sample)
			report, err := evaluateHeadroom(c, sample)
			if (err != nil) != test.invalid {
				t.Fatal("counter validation differs", err)
			}
			if report.Ready != (test.name == "exact-boundary") {
				t.Fatal("headroom decision differs")
			}
		})
	}
	c.MemoryMB = 8192
	r, err := evaluateHeadroom(c, headroomSample())
	if err != nil || r.Ready || r.PhysicalRequiredBytes != 14<<30 || r.CommitRequiredBytes != 10<<30 {
		t.Fatal("large guest did not increase reserves")
	}
}

func TestNativePressureRefusesBeforeDiskOrHCSDispatch(t *testing.T) {
	for _, reason := range []string{"insufficient headroom", "resource counters unavailable"} {
		t.Run(reason, func(t *testing.T) {
			rejected := errors.New(reason)
			calls := 0
			// No DLL is supplied: any HCS dispatch would panic. The synthetic child
			// path is absent, so reaching disk preparation also changes the result.
			api := &native{preparedOwner: "stale", resourceCheck: func(Config) error { calls++; return rejected }}
			if err := api.Prepare(context.Background(), exampleConfig()); !errors.Is(err, rejected) || api.preparedOwner != "" {
				t.Fatal("pressure reached disk preparation", err)
			}
			system, settled, err := api.Create(context.Background(), exampleConfig())
			if !errors.Is(err, rejected) || !settled || system != nil || calls != 2 {
				t.Fatal("pressure reached or left ambiguous native dispatch", err)
			}
		})
	}
}

func TestHeadroomCLIReportsWithoutOpeningImagesOrWritingLabState(t *testing.T) {
	c, j := testJournal(t)
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := RunCLI(context.Background(), []string{"headroom", "--config", path}, &out); err != nil {
		t.Fatal(err)
	}
	var report HeadroomReport
	if json.Unmarshal(out.Bytes(), &report) != nil || report.PhysicalRequiredBytes < 10<<30 || report.CommitRequiredBytes < 6<<30 || report.DiskRequiredBytes != 8<<30 || report.RequiredCPUs != c.CPU+2 {
		t.Fatal("resource report missing fixed reserves")
	}
	if bytes.Contains(out.Bytes(), []byte(c.Root)) || bytes.Contains(out.Bytes(), []byte(c.Baseline)) {
		t.Fatal("resource report exposed configuration paths")
	}
	entries, err := os.ReadDir(j.root.Name())
	if err != nil || len(entries) != 0 {
		t.Fatal("resource-only check changed the trial root")
	}
}

func TestResourceWatchCancelsOnlyTrialAndJoins(t *testing.T) {
	for _, low := range []string{"physical", "commit", "disk", "unavailable"} {
		t.Run(low, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			ticks := make(chan time.Time, 1)
			ticks <- time.Time{}
			report := HeadroomReport{PhysicalAvailableBytes: 6 << 30, CommitAvailableBytes: 2 << 30, DiskAvailableBytes: 8 << 30}
			switch low {
			case "physical":
				report.PhysicalAvailableBytes--
			case "commit":
				report.CommitAvailableBytes--
			case "disk":
				report.DiskAvailableBytes--
			}
			read := func(Config) (HeadroomReport, error) {
				if low == "unavailable" {
					return report, errors.New("counters unavailable")
				}
				return report, nil
			}
			err := watchTrialResources(ctx, exampleConfig(), ticks, read, cancel)
			if err == nil || !errors.Is(context.Cause(ctx), err) {
				t.Fatal("pressure did not cancel the owned trial")
			}
		})
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	ticks := make(chan time.Time)
	done := make(chan error, 1)
	go func() {
		done <- watchTrialResources(ctx, exampleConfig(), ticks, func(Config) (HeadroomReport, error) {
			return HeadroomReport{PhysicalAvailableBytes: 6 << 30, CommitAvailableBytes: 2 << 30, DiskAvailableBytes: 8 << 30}, nil
		}, cancel)
	}()
	ticks <- time.Time{}
	if ctx.Err() != nil {
		t.Fatal("live reserve boundary rejected")
	}
	cancel(nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("resource watcher did not exit")
	}
}
