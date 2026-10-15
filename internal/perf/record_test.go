package perf

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDurationWeightedJobSummaryAndMemoryPeaks(t *testing.T) {
	start := time.Now().UTC()
	r := Report{}
	s := Sample{At: start, TotalBytes: 1000, AvailableBytes: 600, LogicalCPUs: 2}
	r.add(s)
	s.At = start.Add(2 * time.Second)
	s.AvailableBytes = 200
	s.CPUValid = true
	s.CPUPercent = 20
	s.CorePercent = []float64{10, 30}
	r.add(s)
	s.At = start.Add(10 * time.Second)
	s.AvailableBytes = 500
	s.CPUPercent = 80
	s.CorePercent = []float64{70, 90}
	r.add(s)
	if r.CPUAverage != 68 || r.CPUSeconds != 10 || r.CPUPeak != 80 || r.CoreAverage[0] != 58 || r.CorePeak[1] != 90 || r.PeakUsedBytes != 800 || r.MinimumAvailableBytes != 200 || !r.valid() {
		t.Fatal(r)
	}
	s.At = start.Add(11 * time.Second)
	s.CPUValid = false
	s.LogicalCPUs = 1
	s.CorePercent = nil
	r.add(s)
	if r.CPUSeconds != 0 || len(r.CoreAverage) != 0 || !r.valid() {
		t.Fatal("topology change retained mismatched core averages", r)
	}
}

func TestReadReportRejectsMalformedOversizedOrUnboundedGuestData(t *testing.T) {
	directory := t.TempDir()
	for _, content := range []string{"not-json", strings.Repeat("x", 64<<10+1), `{"latest":{"total_bytes":10,"available_bytes":11}}`} {
		if err := os.WriteFile(filepath.Join(directory, FileName), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadReport(directory); err == nil {
			t.Fatal("unsafe guest telemetry accepted")
		}
	}
	var output bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	PrintEnd(ctx, &output, directory)
	if strings.Contains(output.String(), "not-json") || !strings.Contains(output.String(), "sampling unavailable") {
		t.Fatal(output.String())
	}
}

func TestRecorderOwnsLifetimeWaitsForJobAndFlushesCompletion(t *testing.T) {
	if _, err := NewSampler(t.TempDir()).Sample(); err != nil {
		t.Skip("native sampling unavailable")
	}
	directory := t.TempDir()
	stop := StartRecorder(context.Background(), directory, directory)
	defer stop()
	if _, err := os.Stat(filepath.Join(directory, FileName)); !os.IsNotExist(err) {
		t.Fatal("idle runner sampled as job")
	}
	if err := os.WriteFile(filepath.Join(directory, "job.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := ReadReport(directory); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("recorder never saw job start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	var output bytes.Buffer
	PrintEnd(context.Background(), &output, directory)
	report, err := ReadReport(directory)
	if err != nil || !report.Complete || !strings.Contains(output.String(), "final_sample=true") {
		t.Fatal(report, err, output.String())
	}
	stop()
	before, err := os.ReadFile(filepath.Join(directory, FileName))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	after, err := os.ReadFile(filepath.Join(directory, FileName))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("stopped recorder wrote again", err)
	}
}

func TestCompletionOutputAdmitsOnlyNumericReportFields(t *testing.T) {
	directory := t.TempDir()
	r := Report{Complete: true}
	r.add(Sample{At: time.Now().UTC(), TotalBytes: 8 << 30, AvailableBytes: 3 << 30, LogicalCPUs: 2, Commit: &CommitSpace{UsedBytes: 6 << 30, LimitBytes: 10 << 30, PeakSinceBootBytes: 7 << 30}})
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(`,"unexpected":"synthetic-private-data"}`)...)
	if err := os.WriteFile(filepath.Join(directory, FileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	PrintEnd(context.Background(), &out, directory)
	if strings.Contains(out.String(), "synthetic-private") || strings.Contains(out.String(), "CPU average=0.0%") || !strings.Contains(out.String(), "CPU unavailable (no interval)") || !strings.Contains(out.String(), "commit sampled job peak=6.00 GiB") {
		t.Fatal(out.String())
	}
}
