//go:build windows

package imagefactory

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
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

func queryDiskInformation(path string) (diskInformation, error) {
	var info diskInformation
	info.Version = 7 // GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE
	h, err := vhd.OpenVirtualDiskWithParameters(path, vhd.VirtualDiskAccessNone, vhd.OpenVirtualDiskFlagNoParents, &vhd.OpenVirtualDiskParameters{Version: 2, Version2: vhd.OpenVersion2{GetInfoOnly: true, ReadOnly: true}})
	if err != nil {
		var code syscall.Errno
		if errors.As(err, &code) {
			return info, fmt.Errorf("cannot inspect immutable VHDX metadata (Win32 %d)", code)
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
func verifyStandalone(path string) error {
	info, err := queryDiskInformation(path)
	if err != nil {
		return err
	}
	subtype := binary.LittleEndian.Uint32(info.Data[:4])
	if subtype != 2 && subtype != 3 {
		return errors.New("generalized source and published image must be standalone VHDX files")
	}
	return nil
}
