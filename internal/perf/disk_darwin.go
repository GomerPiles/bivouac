package perf

import (
	"errors"

	"golang.org/x/sys/unix"
)

func readDiskSpace(directory string) (DiskSpace, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(directory, &fs); err != nil || fs.Bsize == 0 {
		return DiskSpace{}, errors.New("filesystem counters unavailable")
	}
	return diskFromBlocks(fs.Blocks, fs.Bavail, uint64(fs.Bsize))
}
