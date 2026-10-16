package vz

import (
	"os"
	"syscall"
)

func rootSUID(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == 0 && info.Mode()&os.ModeSetuid != 0 && info.Mode().Perm()&0o022 == 0
}
