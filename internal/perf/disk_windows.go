package perf

import (
	"errors"
	"golang.org/x/sys/windows"
)

func readDiskSpace(directory string) (DiskSpace, error) {
	path, err := windows.UTF16PtrFromString(directory)
	if err != nil || directory == "" {
		return DiskSpace{}, errors.New("filesystem counters unavailable")
	}
	var d DiskSpace
	if err := windows.GetDiskFreeSpaceEx(path, &d.AvailableBytes, &d.TotalBytes, nil); err != nil || !d.valid() {
		return DiskSpace{}, errors.New("filesystem counters unavailable")
	}
	return d, nil
}
