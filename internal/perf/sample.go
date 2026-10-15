// Package perf collects bounded numeric performance telemetry. It never reads
// process names, arguments, environment variables or network destinations.
package perf

import (
	"errors"
	"fmt"
	"math"
	"time"
)

const maxCPUs = 256

var ErrUnsupported = errors.New("performance sampling unavailable on this platform")

type cpuTime struct{ busy, total uint64 }
type counters struct {
	commit           *CommitSpace
	cpu              []cpuTime
	total, available uint64
}

// Sample describes the whole host or guest, not one process. CPU percentages
// cover the interval since the preceding sample; cores are logical processors.
type Sample struct {
	At             time.Time    `json:"at"`
	TotalBytes     uint64       `json:"total_bytes"`
	AvailableBytes uint64       `json:"available_bytes"`
	LogicalCPUs    int          `json:"logical_cpus"`
	CPUValid       bool         `json:"cpu_valid"`
	CPUPercent     float64      `json:"cpu_percent"`
	CorePercent    []float64    `json:"core_percent,omitempty"`
	Disk           *DiskSpace   `json:"disk,omitempty"`
	Commit         *CommitSpace `json:"commit,omitempty"`
}

// Sampler owns its prior counters. Use one sampler per observation stream.
type Sampler struct {
	read     func() (counters, error)
	readDisk func() (DiskSpace, error)
	previous counters
}

// NewSampler samples the filesystem containing directory without retaining its
// path in telemetry. Disk read failure leaves CPU and memory sampling intact.
func NewSampler(directory string) *Sampler {
	return &Sampler{read: readCounters, readDisk: func() (DiskSpace, error) { return readDiskSpace(directory) }}
}

func (s *Sampler) Sample() (Sample, error) {
	c, err := s.read()
	if err != nil {
		s.previous = counters{}
		return Sample{}, err
	}
	if c.total == 0 || c.available > c.total || len(c.cpu) == 0 || len(c.cpu) > maxCPUs {
		s.previous = counters{}
		return Sample{}, errors.New("invalid performance counters")
	}
	result := Sample{At: time.Now().UTC(), TotalBytes: c.total, AvailableBytes: c.available, LogicalCPUs: len(c.cpu)}
	if c.commit != nil && c.commit.valid() {
		copy := *c.commit
		result.Commit = &copy
	}
	if s.readDisk != nil {
		if disk, err := s.readDisk(); err == nil && disk.valid() {
			result.Disk = &disk
		}
	}
	if len(s.previous.cpu) == len(c.cpu) {
		result.CPUValid = true
		var busy, total float64
		for i, now := range c.cpu {
			before := s.previous.cpu[i]
			if now.total <= before.total || now.busy < before.busy || now.busy-before.busy > now.total-before.total {
				result.CPUValid = false
				break
			}
			b, t := float64(now.busy-before.busy), float64(now.total-before.total)
			result.CorePercent = append(result.CorePercent, round(100*b/t))
			busy += b
			total += t
		}
		if result.CPUValid {
			result.CPUPercent = round(100 * busy / total)
		} else {
			result.CorePercent = nil
		}
	}
	s.previous = c
	return result, nil
}

func round(n float64) float64 { return math.Round(n*10) / 10 }
func percent(n float64) bool  { return !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 0 && n <= 100 }
func (s Sample) valid() bool {
	if s.Commit != nil && !s.Commit.valid() {
		return false
	}
	if s.Disk != nil && !s.Disk.valid() {
		return false
	}
	if s.TotalBytes == 0 || s.AvailableBytes > s.TotalBytes || s.LogicalCPUs < 1 || s.LogicalCPUs > maxCPUs || !percent(s.CPUPercent) {
		return false
	}
	if s.CPUValid && len(s.CorePercent) != s.LogicalCPUs || !s.CPUValid && len(s.CorePercent) != 0 {
		return false
	}
	for _, n := range s.CorePercent {
		if !percent(n) {
			return false
		}
	}
	return true
}

func (s Sample) String() string {
	cpu := "unavailable (baseline)"
	if s.CPUValid {
		cpu = fmt.Sprintf("%.1f%%; logical CPU %%=%v", s.CPUPercent, s.CorePercent)
	}
	disk := "unavailable"
	if s.Disk != nil {
		disk = fmt.Sprintf("%.2f/%.2f GiB available", float64(s.Disk.AvailableBytes)/(1<<30), float64(s.Disk.TotalBytes)/(1<<30))
	}
	commit := "unavailable"
	if s.Commit != nil {
		commit = s.Commit.String()
	}
	return fmt.Sprintf("physical memory %.2f/%.2f GiB used, %.2f GiB available; commit %s; CPU %s; logical CPUs=%d; runner disk %s", float64(s.TotalBytes-s.AvailableBytes)/(1<<30), float64(s.TotalBytes)/(1<<30), float64(s.AvailableBytes)/(1<<30), commit, cpu, s.LogicalCPUs, disk)
}
