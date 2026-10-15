package perf

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCommitPagesAndBounds(t *testing.T) {
	c, ok := commitFromPages(3, 8, 5, 4096)
	if !ok || c.UsedBytes != 12288 || c.LimitBytes != 32768 || c.PeakSinceBootBytes != 20480 || c.HeadroomBytes() != 20480 {
		t.Fatal(c, ok)
	}
	for _, pages := range [][4]uint64{{0, 0, 0, 4096}, {9, 8, 9, 4096}, {3, 8, 2, 4096}, {3, 8, 5, 0}, {math.MaxUint64, 8, math.MaxUint64, 4096}, {3, math.MaxUint64, 5, 4096}, {3, 8, math.MaxUint64, 4096}} {
		if _, ok := commitFromPages(pages[0], pages[1], pages[2], pages[3]); ok {
			t.Fatal("invalid page counts accepted", pages)
		}
	}
	for _, used := range []uint64{0, 8} {
		if _, ok := commitFromPages(used, 8, 8, 4096); !ok {
			t.Fatal("valid empty/full commit rejected")
		}
	}
}

func TestCommitPressureIndependentOfPhysicalAvailability(t *testing.T) {
	const gib = uint64(1 << 30)
	r := Report{Complete: true}
	r.add(Sample{At: time.Now().UTC(), TotalBytes: 18 * gib, AvailableBytes: 12 * gib, LogicalCPUs: 2,
		Commit: &CommitSpace{UsedBytes: 18*gib - gib/4, LimitBytes: 18 * gib, PeakSinceBootBytes: 18 * gib}})
	if !r.valid() || r.Commit.MinimumHeadroomBytes != gib/4 || r.Commit.PeakPercent < 98 {
		t.Fatal(r)
	}
	directory := t.TempDir()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, FileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	PrintEnd(context.Background(), &output, directory)
	for _, text := range []string{"peak physical memory used=6.00/18.00 GiB", "minimum physical available=12.00 GiB", "commit sampled job peak=17.75 GiB (peak usage=98.6%)", "minimum headroom=0.25 GiB", "OS peak since boot=18.00 GiB"} {
		if !strings.Contains(output.String(), text) {
			t.Fatal("missing distinct physical/commit value", text, output.String())
		}
	}
}

func TestCommitSummaryHandlesChangingLimitsAndMissingReads(t *testing.T) {
	start := time.Now().UTC()
	r := Report{}
	s := Sample{At: start, TotalBytes: 100, AvailableBytes: 80, LogicalCPUs: 1, Commit: &CommitSpace{UsedBytes: 90, LimitBytes: 100, PeakSinceBootBytes: 110}}
	r.add(s)
	s.At = start.Add(time.Second)
	s.Commit = &CommitSpace{UsedBytes: 110, LimitBytes: 200, PeakSinceBootBytes: 110}
	r.add(s)
	s.At = start.Add(2 * time.Second)
	s.Commit = nil
	r.add(s)
	if !r.valid() || r.Samples != 3 || r.Commit.Samples != 2 || r.Commit.PeakUsedBytes != 110 || r.Commit.PeakPercent != 90 || r.Commit.MinimumHeadroomBytes != 10 || r.Commit.Latest.LimitBytes != 200 || !r.Commit.LatestAt.Equal(start.Add(time.Second)) {
		t.Fatal(r)
	}
	valid := *r.Commit
	for _, mutate := range []func(*CommitReport){
		func(c *CommitReport) { c.Samples = 4 },
		func(c *CommitReport) { c.LatestAt = start.Add(-time.Second) },
		func(c *CommitReport) { c.LatestAt = s.At.Add(time.Second) },
		func(c *CommitReport) { c.PeakUsedBytes = 109 },
		func(c *CommitReport) { c.PeakUsedBytes = 111 },
		func(c *CommitReport) { c.PeakPercent = math.NaN() },
		func(c *CommitReport) { c.PeakPercent = 101 },
		func(c *CommitReport) { c.PeakPercent = 54 },
		func(c *CommitReport) { c.MinimumHeadroomBytes = 91 },
		func(c *CommitReport) { c.Latest.UsedBytes = 201 },
	} {
		c := valid
		mutate(&c)
		r.Commit = &c
		data, err := json.Marshal(r)
		if err != nil {
			continue // Non-finite numeric values cannot be encoded either.
		}
		if _, err := DecodeReport(bytes.NewReader(data)); err == nil {
			t.Fatal("invalid untrusted commit report accepted", c)
		}
	}
}

func TestCommitReadFailurePreservesCPUAndPhysicalTelemetry(t *testing.T) {
	s := &Sampler{}
	var busy uint64
	for i, commit := range []*CommitSpace{nil, {UsedBytes: 101, LimitBytes: 100, PeakSinceBootBytes: 101}, {UsedBytes: 30, LimitBytes: 100, PeakSinceBootBytes: 40}} {
		busy++
		s.read = func() (counters, error) {
			return counters{cpu: []cpuTime{{busy, busy * 10}}, total: 100, available: 80, commit: commit}, nil
		}
		result, err := s.Sample()
		if err != nil || !result.valid() || result.AvailableBytes != 80 || result.CPUValid != (i > 0) || (result.Commit != nil) != (i == 2) {
			t.Fatal(result, err)
		}
		if i == 2 {
			commit.UsedBytes = 99
			if result.Commit.UsedBytes != 30 {
				t.Fatal("sample retained mutable source alias")
			}
		}
	}
}
