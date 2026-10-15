//go:build !windows

package perf

import "os"

func openReport(path string) (*os.File, error) { return os.Open(path) }
