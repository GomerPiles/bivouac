//go:build windows

package hcsspike

import (
	"context"
	"errors"
	"time"

	"github.com/GomerPiles/bivouac/internal/perf"
)

// HeadroomReport contains only current resource counts and fixed reserves.
// It is a point-in-time admission check, not a reservation against other users.
type HeadroomReport struct {
	Ready                  bool   `json:"ready"`
	PhysicalAvailableBytes uint64 `json:"physical_available_bytes"`
	PhysicalRequiredBytes  uint64 `json:"physical_required_bytes"`
	CommitAvailableBytes   uint64 `json:"commit_available_bytes"`
	CommitRequiredBytes    uint64 `json:"commit_required_bytes"`
	DiskAvailableBytes     uint64 `json:"disk_available_bytes"`
	DiskRequiredBytes      uint64 `json:"disk_required_bytes"`
	LogicalCPUs            int    `json:"logical_cpus"`
	RequiredCPUs           int    `json:"required_cpus"`
}

// Headroom reads ordinary-token counters for the trial root's filesystem and
// host memory/CPU totals. It opens no image, HCS VM, or production state.
func Headroom(c Config) (HeadroomReport, error) {
	if err := c.Validate(); err != nil {
		return HeadroomReport{}, err
	}
	sample, err := perf.NewSampler(c.Root).Sample()
	if err != nil {
		return HeadroomReport{}, errors.New("cannot read isolated-trial resource counters")
	}
	return evaluateHeadroom(c, sample)
}

func evaluateHeadroom(c Config, sample perf.Sample) (HeadroomReport, error) {
	if c.MemoryMB < 1024 || c.MemoryMB > 8192 || c.CPU < 1 || c.CPU > 4 || sample.TotalBytes == 0 || sample.AvailableBytes > sample.TotalBytes || sample.LogicalCPUs < 1 || sample.Commit == nil || sample.Commit.LimitBytes == 0 || sample.Commit.UsedBytes > sample.Commit.LimitBytes || sample.Disk == nil || sample.Disk.TotalBytes == 0 || sample.Disk.AvailableBytes > sample.Disk.TotalBytes {
		return HeadroomReport{}, errors.New("isolated-trial resource counters unavailable or invalid")
	}
	guestBytes := uint64(c.MemoryMB) << 20 // #nosec G115 -- Validated above to the fixed 1024-8192 MiB range.
	r := HeadroomReport{
		PhysicalAvailableBytes: sample.AvailableBytes,
		PhysicalRequiredBytes:  max(10<<30, guestBytes+(6<<30)),
		CommitAvailableBytes:   sample.Commit.HeadroomBytes(),
		CommitRequiredBytes:    max(6<<30, guestBytes+(2<<30)),
		DiskAvailableBytes:     sample.Disk.AvailableBytes,
		DiskRequiredBytes:      8 << 30,
		LogicalCPUs:            sample.LogicalCPUs,
		RequiredCPUs:           c.CPU + 2,
	}
	r.Ready = r.PhysicalAvailableBytes >= r.PhysicalRequiredBytes && r.CommitAvailableBytes >= r.CommitRequiredBytes && r.DiskAvailableBytes >= r.DiskRequiredBytes && r.LogicalCPUs >= r.RequiredCPUs
	return r, nil
}

func requireHeadroom(c Config) error {
	r, err := Headroom(c)
	if err != nil {
		return err
	}
	if !r.Ready {
		return errors.New("insufficient host headroom for isolated HCS trial")
	}
	return nil
}

func (a *native) requireHeadroom(c Config) error {
	if a.resourceCheck != nil {
		return a.resourceCheck(c)
	}
	return requireHeadroom(c)
}

// Cancel only the isolated trial if host pressure consumes the reserve after
// admission. trial's independent owned cleanup still runs before this returns.
func guardTrialResources(ctx context.Context, c Config, run func(context.Context) (Report, error)) (Report, error) {
	guarded, cancel := context.WithCancelCause(ctx)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	done := make(chan error, 1)
	go func() { done <- watchTrialResources(guarded, c, ticker.C, Headroom, cancel) }()
	report, err := run(guarded)
	cancel(nil)
	return report, errors.Join(err, <-done)
}

func watchTrialResources(ctx context.Context, c Config, ticks <-chan time.Time, read func(Config) (HeadroomReport, error), cancel context.CancelCauseFunc) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticks:
			r, err := read(c)
			if err == nil && (r.PhysicalAvailableBytes < 6<<30 || r.CommitAvailableBytes < 2<<30 || r.DiskAvailableBytes < 8<<30) {
				err = errors.New("host reserve lost; stopping only the isolated HCS trial")
			}
			if err != nil {
				cancel(err)
				return err
			}
		}
	}
}
