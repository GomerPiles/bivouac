package perf

import "errors"

// DiskSpace is caller-available filesystem capacity, not physical disk size or
// per-job storage usage. Reserved blocks and user quotas reduce availability.
type DiskSpace struct {
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

func (d DiskSpace) valid() bool { return d.TotalBytes > 0 && d.AvailableBytes <= d.TotalBytes }

func diskFromBlocks(blocks, available, blockSize uint64) (DiskSpace, error) {
	if blockSize == 0 || blocks == 0 || available > blocks || blocks > ^uint64(0)/blockSize {
		return DiskSpace{}, errors.New("filesystem counters unavailable")
	}
	return DiskSpace{TotalBytes: blocks * blockSize, AvailableBytes: available * blockSize}, nil
}
