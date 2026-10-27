package vm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// CloneFactory clones only a stopped hidden factory candidate into a fresh,
// hidden gate directory on the same APFS volume. Public Clone name rules stay strict.
func (h Store) CloneFactory(build, gate string) error {
	if !factoryName(build, ".build-") || !factoryName(gate, ".gate-") {
		return errors.New("invalid factory clone names")
	}
	src, dst := h.Dir(build), h.Dir(gate)
	if err := plainDirectory(src); err != nil {
		return err
	}
	pid, err := Holder(src)
	if err != nil || pid != 0 {
		return errors.New("factory candidate is not stopped")
	}
	m, err := ReadManifest(src)
	if err != nil {
		return err
	}
	if m.MAC, err = randomMAC(); err != nil {
		return err
	}
	if err = os.Mkdir(dst, 0700); err != nil {
		return err
	}
	for _, name := range []string{DiskFile, NVRAMFile} {
		if err := unix.Clonefile(filepath.Join(src, name), filepath.Join(dst, name), unix.CLONE_NOFOLLOW); err != nil {
			return err
		}
	}
	return WriteManifest(dst, m)
}
func factoryName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+32 {
		return false
	}
	for _, c := range strings.TrimPrefix(name, prefix) {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func plainDirectory(path string) error {
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return errors.New("factory directory is not a plain directory")
	}
	return nil
}
