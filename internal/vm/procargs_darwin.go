package vm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"

	"golang.org/x/sys/unix"
)

// ErrForeignHolder reports a VM lock held by something other than a bivouac
// VM helper for that directory (for example `tart run`); it is never signalled.
var ErrForeignHolder = errors.New("VM is held by a process that is not its bivouac helper")

// HelperPID returns the pid of the bivouac helper running dir, 0 when the VM
// is stopped, or ErrForeignHolder.
func HelperPID(dir string) (int, error) {
	pid, err := Holder(dir)
	if err != nil || pid == 0 {
		return pid, err
	}
	args, err := processArgs(pid)
	if err != nil {
		return 0, err
	}
	if !isHelper(args, dir) {
		return 0, ErrForeignHolder
	}
	return pid, nil
}

// isHelper matches `<exe> vm run --dir <dir> ...`, the shape Args produces.
func isHelper(args []string, dir string) bool {
	return len(args) >= 5 && slices.Equal(args[1:5], []string{"vm", "run", "--dir", dir})
}

// processArgs reads a process's argv from kern.procargs2: argc, the exec
// path, NUL padding, then argc NUL-terminated arguments.
func processArgs(pid int) ([]string, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, errors.New("short process arguments")
	}
	argc := int(binary.LittleEndian.Uint32(buf))
	rest := buf[4:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return nil, errors.New("malformed process arguments")
	}
	rest = bytes.TrimLeft(rest[end:], "\x00")
	args := make([]string, 0, argc)
	for range argc {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			return nil, errors.New("malformed process arguments")
		}
		args = append(args, string(rest[:end]))
		rest = rest[end+1:]
	}
	return args, nil
}
