//go:build windows

package vmhost

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/Microsoft/go-winio/vhd"
	"golang.org/x/sys/windows"
)

// Flatten writes a new single-file VHDX holding the logical contents of
// source and its whole parent chain. The source chain is opened read-only and
// never written; an existing destination is refused.
func Flatten(source, destination string) error {
	if !localAbsolute(source) || !localAbsolute(destination) {
		return errors.New("flatten paths must be local and absolute")
	}
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	params := &vhd.CreateVirtualDiskParameters{Version: 2, Version2: vhd.CreateVersion2{SourcePath: from}}
	handle, err := vhd.CreateVirtualDisk(destination, vhd.VirtualDiskAccessNone, vhd.CreateVirtualDiskFlagPreventWritesToSourceDisk, params)
	if err != nil {
		return fmt.Errorf("cannot flatten image: %w", err)
	}
	return syscall.CloseHandle(handle)
}
