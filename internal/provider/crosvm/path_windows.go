//go:build windows

package crosvm

import (
	"io/fs"
	"strings"

	"golang.org/x/sys/windows"
)

// resolvePath returns the final path of an existing file or directory, as the
// file system names it once opened: symlinks, junctions and other mount
// points followed, 8.3 short names expanded and case as stored. Running
// images are resolved the same way (see processImage). Since Go 1.23,
// filepath.EvalSymlinks no longer follows junctions or mount points.
func resolvePath(path string) (string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	// Querying the name needs no access rights, so no share mode can conflict
	// and nothing is read. Backup semantics permits opening a directory.
	h, err := windows.CreateFile(name, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", &fs.PathError{Op: "open", Path: path, Err: err}
	}
	defer func() { _ = windows.CloseHandle(h) }()
	// FILE_NAME_NORMALIZED | VOLUME_NAME_DOS; x/sys/windows names neither.
	const flags = 0
	var buf [windows.MAX_LONG_PATH]uint16
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), flags)
	if err != nil {
		return "", &fs.PathError{Op: "resolve", Path: path, Err: err}
	}
	// A result that does not fit reports the size it needs instead.
	if n >= uint32(len(buf)) {
		return "", &fs.PathError{Op: "resolve", Path: path, Err: windows.ERROR_FILENAME_EXCED_RANGE}
	}
	return trimFinalPrefix(windows.UTF16ToString(buf[:n])), nil
}

// trimFinalPrefix converts the extended-length form GetFinalPathNameByHandle
// returns into an ordinary drive or UNC path.
func trimFinalPrefix(path string) string {
	if rest, ok := strings.CutPrefix(path, `\\?\UNC\`); ok {
		return `\\` + rest
	}
	return strings.TrimPrefix(path, `\\?\`)
}
