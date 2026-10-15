//go:build !windows && !linux && !darwin

package perf

func readCounters() (counters, error) { return counters{}, ErrUnsupported }
