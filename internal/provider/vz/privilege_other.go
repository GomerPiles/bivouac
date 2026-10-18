//go:build !darwin

package vz

import "os"

func rootSUID(os.FileInfo) bool { return false }
