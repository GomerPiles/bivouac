package perf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"
)

const FileName = "performance.json"

// Report keeps constant-space, duration-weighted CPU averages and sampled
// peaks. It contains only numeric telemetry; a failed read never fails a job.
type Report struct {
	StartedAt             time.Time     `json:"started_at"`
	Latest                Sample        `json:"latest"`
	Complete              bool          `json:"complete"`
	Samples               int           `json:"samples"`
	CPUSeconds            float64       `json:"cpu_seconds"`
	CPUAverage            float64       `json:"cpu_average"`
	CPUPeak               float64       `json:"cpu_peak"`
	CoreAverage           []float64     `json:"core_average,omitempty"`
	CorePeak              []float64     `json:"core_peak,omitempty"`
	PeakUsedBytes         uint64        `json:"peak_used_bytes"`
	MinimumAvailableBytes uint64        `json:"minimum_available_bytes"`
	Disk                  *DiskReport   `json:"disk,omitempty"`
	Commit                *CommitReport `json:"commit,omitempty"`
}

// DiskReport retains the most recent successful disk sample independently of
// transient reads. A capacity change starts a new disk observation window.
type DiskReport struct {
	Latest                DiskSpace `json:"latest"`
	Samples               int       `json:"samples"`
	MinimumAvailableBytes uint64    `json:"minimum_available_bytes"`
}

func (r *Report) add(s Sample) {
	if !s.valid() {
		return
	}
	if r.StartedAt.IsZero() {
		r.StartedAt = s.At
		r.MinimumAvailableBytes = s.AvailableBytes
	}
	used := s.TotalBytes - s.AvailableBytes
	r.PeakUsedBytes = max(r.PeakUsedBytes, used)
	r.MinimumAvailableBytes = min(r.MinimumAvailableBytes, s.AvailableBytes)
	seconds := s.At.Sub(r.Latest.At).Seconds()
	if len(r.CoreAverage) > 0 && len(r.CoreAverage) != s.LogicalCPUs {
		r.CPUSeconds = 0
		r.CPUAverage = 0
		r.CPUPeak = 0
		r.CoreAverage = nil
		r.CorePeak = nil
	}
	if s.CPUValid && seconds > 0 && !r.Latest.At.IsZero() {
		// Topology changes reset CPU aggregates; never combine unlike cores.
		if len(r.CoreAverage) != s.LogicalCPUs {
			r.CPUSeconds = 0
			r.CPUAverage = 0
			r.CPUPeak = 0
			r.CoreAverage = make([]float64, s.LogicalCPUs)
			r.CorePeak = make([]float64, s.LogicalCPUs)
		}
		total := r.CPUSeconds + seconds
		r.CPUAverage = (r.CPUAverage*r.CPUSeconds + s.CPUPercent*seconds) / total
		r.CPUPeak = max(r.CPUPeak, s.CPUPercent)
		for i, n := range s.CorePercent {
			r.CoreAverage[i] = (r.CoreAverage[i]*r.CPUSeconds + n*seconds) / total
			r.CorePeak[i] = max(r.CorePeak[i], n)
		}
		r.CPUSeconds = total
	}
	r.Latest = s
	r.Samples++
	if s.Commit != nil {
		if r.Commit == nil {
			r.Commit = &CommitReport{}
		}
		r.Commit.add(s.At, *s.Commit)
	}
	if s.Disk != nil {
		if r.Disk == nil || r.Disk.Latest.TotalBytes != s.Disk.TotalBytes {
			r.Disk = &DiskReport{MinimumAvailableBytes: s.Disk.AvailableBytes}
		}
		r.Disk.Latest = *s.Disk
		r.Disk.Samples++
		r.Disk.MinimumAvailableBytes = min(r.Disk.MinimumAvailableBytes, s.Disk.AvailableBytes)
	}
}

func (r Report) valid() bool {
	if r.Commit != nil && !r.Commit.valid(r) {
		return false
	}
	if r.Disk != nil && (!r.Disk.Latest.valid() || r.Disk.Samples < 1 || r.Disk.Samples > r.Samples || r.Disk.MinimumAvailableBytes > r.Disk.Latest.AvailableBytes) {
		return false
	}
	if !r.Latest.valid() || r.StartedAt.IsZero() || r.Latest.At.Before(r.StartedAt) || r.Samples < 1 || r.CPUSeconds < 0 || r.CPUSeconds > 365*24*3600 || math.IsNaN(r.CPUSeconds) || !percent(r.CPUAverage) || !percent(r.CPUPeak) || r.PeakUsedBytes > r.Latest.TotalBytes || r.MinimumAvailableBytes > r.Latest.TotalBytes {
		return false
	}
	if len(r.CoreAverage) > maxCPUs || len(r.CorePeak) != len(r.CoreAverage) {
		return false
	}
	for i, n := range r.CoreAverage {
		if !percent(n) || !percent(r.CorePeak[i]) {
			return false
		}
	}
	return true
}

func save(root *os.Root, r Report) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err = root.WriteFile(FileName+".new", data, 0o600); err != nil {
		return err
	}
	return root.Rename(FileName+".new", FileName)
}

// StartRecorder returns an owned stop function which joins its goroutine. The
// listener calls it on every exit. No child process or external service exists.
// Sampling begins only after the official job-start hook records job.json.
func StartRecorder(parent context.Context, directory, diskDirectory string) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() { defer close(done); record(ctx, directory, diskDirectory) }()
	return func() { cancel(); <-done }
}

func record(ctx context.Context, directory, diskDirectory string) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	sampler := NewSampler(diskDirectory)
	r := Report{}
	var nextSample time.Time
	for {
		if _, err := root.Stat("job.json"); err == nil {
			_, completed := root.Stat("performance.done")
			complete := completed == nil
			flushed := false
			if !time.Now().Before(nextSample) || complete || ctx.Err() != nil {
				nextSample = time.Now().Add(5 * time.Second)
				sampled := false
				if s, err := sampler.Sample(); err == nil {
					r.add(s)
					sampled = true
				}
				if !r.StartedAt.IsZero() {
					r.Complete = complete && sampled
					flushed = save(root, r) == nil
				}
			}
			if complete && r.Complete && flushed {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// ReadReport distrusts the guest file and admits only bounded numeric fields.
func ReadReport(directory string) (Report, error) {
	f, err := openReport(filepath.Join(directory, FileName))
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = f.Close() }()
	return DecodeReport(f)
}

// DecodeReport validates a bounded numeric report at the untrusted archive
// boundary. Callers re-encode the result so unknown guest fields cannot persist.
func DecodeReport(input io.Reader) (Report, error) {
	data, err := io.ReadAll(io.LimitReader(input, 64<<10+1))
	defer clear(data)
	var r Report
	if err != nil || len(data) > 64<<10 || json.Unmarshal(data, &r) != nil || !r.valid() {
		return r, errors.New("invalid performance report")
	}
	return r, nil
}

func PrintStart(out io.Writer, diskDirectory string) {
	s, err := NewSampler(diskDirectory).Sample()
	if err != nil {
		_, _ = fmt.Fprintln(out, "[bivouac performance] start: sampling unavailable")
		return
	}
	_, _ = fmt.Fprintln(out, "[bivouac performance] start:", s.String())
}

// PrintEnd allows at most two seconds for the listener's final sample. Hooks
// always succeed even if telemetry is unsupported, unavailable or corrupted.
func PrintEnd(ctx context.Context, out io.Writer, directory string) {
	root, err := os.OpenRoot(directory)
	if err == nil {
		_ = root.WriteFile("performance.done", []byte("complete\n"), 0o600)
		_ = root.Close()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var r Report
	for {
		r, err = ReadReport(directory)
		if err == nil && r.Complete {
			break
		}
		select {
		case <-ctx.Done():
			goto finished
		case <-time.After(50 * time.Millisecond):
		}
	}
finished:
	if err != nil {
		_, _ = fmt.Fprintln(out, "[bivouac performance] finish: sampling unavailable")
		return
	}
	cpu := "unavailable (no interval)"
	if r.CPUSeconds > 0 {
		cpu = fmt.Sprintf("average=%.1f%% peak=%.1f%%", r.CPUAverage, r.CPUPeak)
	}
	disk := "unavailable"
	if r.Disk != nil {
		disk = fmt.Sprintf("minimum available=%.2f GiB; latest=%.2f/%.2f GiB available; samples=%d", float64(r.Disk.MinimumAvailableBytes)/(1<<30), float64(r.Disk.Latest.AvailableBytes)/(1<<30), float64(r.Disk.Latest.TotalBytes)/(1<<30), r.Disk.Samples)
	}
	commit := "unavailable"
	if r.Commit != nil {
		commit = fmt.Sprintf("sampled job peak=%.2f GiB (peak usage=%.1f%%); minimum headroom=%.2f GiB; latest successful=%s; samples=%d", float64(r.Commit.PeakUsedBytes)/(1<<30), r.Commit.PeakPercent, float64(r.Commit.MinimumHeadroomBytes)/(1<<30), r.Commit.Latest.String(), r.Commit.Samples)
	}
	_, _ = fmt.Fprintf(out, "[bivouac performance] finish: sampled duration=%.1fs; samples=%d; final_sample=%t; peak physical memory used=%.2f/%.2f GiB; minimum physical available=%.2f GiB; commit %s; CPU %s; runner disk %s\n", r.Latest.At.Sub(r.StartedAt).Seconds(), r.Samples, r.Complete, float64(r.PeakUsedBytes)/(1<<30), float64(r.Latest.TotalBytes)/(1<<30), float64(r.MinimumAvailableBytes)/(1<<30), commit, cpu, disk)
	if r.CPUSeconds > 0 {
		average, peak := append([]float64(nil), r.CoreAverage...), append([]float64(nil), r.CorePeak...)
		for i := range average {
			average[i] = round(average[i])
			peak[i] = round(peak[i])
		}
		_, _ = fmt.Fprintf(out, "[bivouac performance] logical CPU utilization %%: average=%v peak=%v\n", average, peak)
	}
}
