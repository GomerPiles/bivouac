package perf

import (
	"errors"
	"math"
	"testing"
)

func TestCPUIntervalsBaselineResetAndWeighting(t *testing.T) {
	sequence := []counters{
		{cpu: []cpuTime{{10, 100}, {20, 200}}, total: 1000, available: 600},
		{cpu: []cpuTime{{60, 200}, {40, 400}}, total: 1000, available: 200},
		{cpu: []cpuTime{{1, 10}, {1, 10}}, total: 1000, available: 500},
		{cpu: []cpuTime{{2, 20}}, total: 1000, available: 500},
	}
	s := &Sampler{read: func() (counters, error) { c := sequence[0]; sequence = sequence[1:]; return c, nil }}
	first, err := s.Sample()
	if err != nil || first.CPUValid || first.LogicalCPUs != 2 {
		t.Fatal(first, err)
	}
	next, err := s.Sample()
	if err != nil || !next.CPUValid || next.CPUPercent != 23.3 || next.CorePercent[0] != 50 || next.CorePercent[1] != 10 {
		t.Fatal(next, err)
	}
	for range 2 {
		sample, err := s.Sample()
		if err != nil || sample.CPUValid {
			t.Fatal("reset/topology yielded fabricated CPU", sample, err)
		}
	}
}

func TestSampleFailureClearsBaselineAndRejectsInvalidCounters(t *testing.T) {
	s := &Sampler{read: func() (counters, error) { return counters{cpu: []cpuTime{{1, 10}}, total: 100, available: 10}, nil }}
	if _, err := s.Sample(); err != nil {
		t.Fatal(err)
	}
	s.read = func() (counters, error) { return counters{}, errors.New("unavailable") }
	if _, err := s.Sample(); err == nil || len(s.previous.cpu) != 0 {
		t.Fatal("failed sampling kept baseline")
	}
	s.read = func() (counters, error) { return counters{cpu: []cpuTime{{1, 10}}, total: 100, available: 200}, nil }
	if _, err := s.Sample(); err == nil {
		t.Fatal("impossible memory accepted")
	}
}

func TestTelemetryValidationBounds(t *testing.T) {
	for _, sample := range []Sample{
		{TotalBytes: 100, AvailableBytes: 101, LogicalCPUs: 1},
		{TotalBytes: 100, LogicalCPUs: 257},
		{TotalBytes: 100, LogicalCPUs: 1, CPUPercent: math.NaN()},
		{TotalBytes: 100, LogicalCPUs: 1, CPUValid: true, CorePercent: []float64{101}},
		{TotalBytes: 100, LogicalCPUs: 1, CPUValid: true, CorePercent: []float64{}},
	} {
		if sample.valid() {
			t.Fatal("invalid telemetry accepted", sample)
		}
	}
}
