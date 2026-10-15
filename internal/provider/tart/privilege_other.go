//go:build !darwin

package tart

import "os"

func rootSUID(os.FileInfo) bool { return false }
