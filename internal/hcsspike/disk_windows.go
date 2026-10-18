//go:build windows

package hcsspike

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Microsoft/go-winio/vhd"
	"golang.org/x/sys/windows"
)

func openReadOnlyPinned(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("invalid immutable file path")
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New("cannot pin immutable file read-only")
	}
	return os.NewFile(uintptr(h), path), nil
}

// DWORD Version + padding + the documented 8-byte-aligned union. The parent
// string is read only inside the API's bounded result buffer, never logged.
type diskInformation struct {
	Version uint32
	Padding uint32
	Data    [32760]byte
}

func queryDiskInformation(path string, version uint32, noParents bool) (diskInformation, error) {
	var info diskInformation
	info.Version = version
	flags := vhd.OpenVirtualDiskFlagNone
	if noParents {
		flags = vhd.OpenVirtualDiskFlagNoParents
	}
	h, err := vhd.OpenVirtualDiskWithParameters(path, vhd.VirtualDiskAccessNone, flags, &vhd.OpenVirtualDiskParameters{Version: 2, Version2: vhd.OpenVersion2{GetInfoOnly: true, ReadOnly: true}})
	if err != nil {
		var code syscall.Errno
		if errors.As(err, &code) {
			return info, fmt.Errorf("cannot inspect immutable VHDX metadata (Win32 %d)", uint32(code))
		}
		return info, errors.New("cannot inspect immutable VHDX metadata")
	}
	defer func() { _ = windows.CloseHandle(windows.Handle(h)) }()
	size := uint32(unsafe.Sizeof(info))
	var used uint32
	proc := windows.NewLazySystemDLL("virtdisk.dll").NewProc("GetVirtualDiskInformation")
	if proc.Find() != nil {
		return info, errors.New("virtual disk information API unavailable")
	}
	code, _, _ := proc.Call(uintptr(h), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&used))) // #nosec G103 -- Documented virtdisk ABI with a bounded aligned output buffer.
	if code != 0 || size > uint32(unsafe.Sizeof(info)) || used > uint32(unsafe.Sizeof(info)) {
		return info, errors.New("immutable VHDX metadata query failed")
	}
	return info, nil
}
func verifyDiskChain(path, parent string) error {
	info, err := queryDiskInformation(path, 7, true)
	if err != nil {
		return err
	}
	subtype := binary.LittleEndian.Uint32(info.Data[:4])
	if parent == "" {
		if subtype != 2 && subtype != 3 {
			return errors.New("generalized source must be a standalone VHDX")
		}
		return nil
	}
	if subtype != 4 {
		return errors.New("prepared runtime disk must retain its recorded source parent")
	}
	info, err = queryDiskInformation(path, 3, false)
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(info.Data[:4]) != 1 {
		return errors.New("prepared image parent is unresolved")
	}
	words := make([]uint16, 0, 256)
	for i := 4; i+1 < len(info.Data); i += 2 {
		word := binary.LittleEndian.Uint16(info.Data[i : i+2])
		if word == 0 {
			actual := strings.TrimPrefix(windows.UTF16ToString(words), `\\?\`)
			// Windows may report a long path for a caller's 8.3 alias. File
			// identity, rather than spelling, must match the pinned parent.
			observed, actualErr := os.Stat(actual)
			expected, parentErr := os.Stat(parent)
			if actualErr != nil || parentErr != nil || !observed.Mode().IsRegular() || !expected.Mode().IsRegular() || !os.SameFile(observed, expected) {
				return errors.New("prepared image resolves to a different source parent")
			}
			return nil
		}
		words = append(words, word)
	}
	return errors.New("prepared image parent path exceeds bound")
}
