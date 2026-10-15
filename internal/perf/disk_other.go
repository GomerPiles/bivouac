//go:build !windows && !linux && !darwin

package perf

func readDiskSpace(string) (DiskSpace, error) { return DiskSpace{}, ErrUnsupported }
