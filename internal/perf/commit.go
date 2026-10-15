package perf

import (
	"fmt"
	"time"
)

// CommitSpace reports Windows system-wide backing commitments separately from
// resident physical memory. The current limit can change as pagefiles resize.
type CommitSpace struct {
	UsedBytes          uint64 `json:"used_bytes"`
	LimitBytes         uint64 `json:"limit_bytes"`
	PeakSinceBootBytes uint64 `json:"peak_since_boot_bytes"`
}

func (c CommitSpace) valid() bool {
	return c.LimitBytes > 0 && c.UsedBytes <= c.LimitBytes && c.PeakSinceBootBytes >= c.UsedBytes
}

func (c CommitSpace) HeadroomBytes() uint64 { return c.LimitBytes - c.UsedBytes }
func (c CommitSpace) usagePercent() float64 {
	return 100 * float64(c.UsedBytes) / float64(c.LimitBytes)
}
func (c CommitSpace) String() string {
	return fmt.Sprintf("%.2f/%.2f GiB used (%.1f%%); headroom=%.2f GiB; OS peak since boot=%.2f GiB", float64(c.UsedBytes)/(1<<30), float64(c.LimitBytes)/(1<<30), c.usagePercent(), float64(c.HeadroomBytes())/(1<<30), float64(c.PeakSinceBootBytes)/(1<<30))
}

// CommitReport retains sampled job peaks and the latest successful OS reading.
// Peak percent and minimum headroom use each sample's contemporaneous limit,
// avoiding a misleading ratio when the OS changes its commit limit mid-job.
type CommitReport struct {
	Latest               CommitSpace `json:"latest"`
	LatestAt             time.Time   `json:"latest_at"`
	Samples              int         `json:"samples"`
	PeakUsedBytes        uint64      `json:"peak_used_bytes"`
	PeakPercent          float64     `json:"peak_percent"`
	MinimumHeadroomBytes uint64      `json:"minimum_headroom_bytes"`
}

func (r *CommitReport) add(at time.Time, c CommitSpace) {
	if r.Samples == 0 {
		r.MinimumHeadroomBytes = c.HeadroomBytes()
	}
	r.Latest = c
	r.LatestAt = at
	r.Samples++
	r.PeakUsedBytes = max(r.PeakUsedBytes, c.UsedBytes)
	r.PeakPercent = max(r.PeakPercent, c.usagePercent())
	r.MinimumHeadroomBytes = min(r.MinimumHeadroomBytes, c.HeadroomBytes())
}

func (r CommitReport) valid(report Report) bool {
	return r.Latest.valid() && r.Samples >= 1 && r.Samples <= report.Samples && !r.LatestAt.Before(report.StartedAt) && !r.LatestAt.After(report.Latest.At) && r.PeakUsedBytes >= r.Latest.UsedBytes && r.PeakUsedBytes <= r.Latest.PeakSinceBootBytes && percent(r.PeakPercent) && r.PeakPercent >= r.Latest.usagePercent() && r.MinimumHeadroomBytes <= r.Latest.HeadroomBytes()
}

func commitFromPages(used, limit, peak, pageSize uint64) (CommitSpace, bool) {
	if pageSize == 0 || used > ^uint64(0)/pageSize || limit > ^uint64(0)/pageSize || peak > ^uint64(0)/pageSize {
		return CommitSpace{}, false
	}
	c := CommitSpace{used * pageSize, limit * pageSize, peak * pageSize}
	return c, c.valid()
}
