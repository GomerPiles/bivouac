//go:build windows

package crosvm

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// linkDirectory makes link name the existing directory target: a symlink when
// this token may create one, otherwise a junction, which needs no privilege.
func linkDirectory(target, link string) error {
	err := os.Symlink(target, link)
	if !errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
		return err
	}
	return createJunction(target, link)
}

// createJunction turns a new empty directory at link into a mount point
// (IO_REPARSE_TAG_MOUNT_POINT) for target.
func createJunction(target, link string) error {
	target, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	substitute := utf16.Encode([]rune(`\??\` + target))
	print := utf16.Encode([]rune(target))
	if len(substitute) > windows.MAX_PATH {
		return errors.New("junction target too long")
	}
	substituteBytes := 2 * uint16(len(substitute)) // #nosec G115 -- Bounded to MAX_PATH above.
	printBytes := 2 * uint16(len(print))           // #nosec G115 -- Shorter than substitute.
	// REPARSE_DATA_BUFFER: tag, data length, reserved, then the substitute and
	// print name offsets and lengths in bytes, then both NUL-terminated names.
	dataBytes := 8 + substituteBytes + 2 + printBytes + 2
	buf := make([]byte, 8+int(dataBytes))
	binary.LittleEndian.PutUint32(buf[0:], windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buf[4:], dataBytes)
	binary.LittleEndian.PutUint16(buf[8:], 0)
	binary.LittleEndian.PutUint16(buf[10:], substituteBytes)
	binary.LittleEndian.PutUint16(buf[12:], substituteBytes+2)
	binary.LittleEndian.PutUint16(buf[14:], printBytes)
	names := append(append(append(substitute, 0), print...), 0)
	for i, unit := range names {
		binary.LittleEndian.PutUint16(buf[16+2*i:], unit)
	}
	if err := os.Mkdir(link, 0o700); err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(link)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var returned uint32
	return windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], 8+uint32(dataBytes), nil, 0, &returned, nil)
}
