//go:build windows

package imagefactory

import (
	"encoding/binary"
	"errors"
	"os"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// createDriverTestJunction needs no symlink privilege or shell process.
func createDriverTestJunction(link, target string) error {
	substitute := utf16.Encode([]rune(`\??\` + target))
	printName := utf16.Encode([]rune(target))
	if len(substitute) > 2000 {
		return errors.New("test junction target too long")
	}
	substituteBytes := 2 * uint16(len(substitute)) // #nosec G115 -- Bounded above.
	printBytes := 2 * uint16(len(printName))       // #nosec G115 -- Shorter than substitute.
	dataBytes := 8 + substituteBytes + 2 + printBytes + 2
	buf := make([]byte, 8+int(dataBytes))
	binary.LittleEndian.PutUint32(buf, windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buf[4:], dataBytes)
	binary.LittleEndian.PutUint16(buf[10:], substituteBytes)
	binary.LittleEndian.PutUint16(buf[12:], substituteBytes+2)
	binary.LittleEndian.PutUint16(buf[14:], printBytes)
	names := append(append(append(substitute, 0), printName...), 0)
	for i, unit := range names {
		binary.LittleEndian.PutUint16(buf[16+2*i:], unit)
	}
	if err := os.Mkdir(link, 0700); err != nil {
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
