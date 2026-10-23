//go:build windows

package imagefactory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

type SpaceCheck struct {
	Phase     string `json:"phase"`
	Available uint64 `json:"available_bytes"`
	Required  uint64 `json:"required_bytes"`
	Source    uint64 `json:"source_bytes"`
	Child     uint64 `json:"child_bytes,omitempty"`
}

func requiredSpace(source, child uint64, publication bool) (uint64, error) {
	if source == 0 || source > 256<<30 || child > 256<<30 {
		return 0, errors.New("image disk size exceeds bound")
	}
	if publication {
		return source + child + (5 << 30), nil
	}
	if source > 32<<30 || child == 0 {
		return 0, errors.New("invalid ISO or image size")
	}
	// ISO copy + applied base with 25% filesystem headroom + equal child and flatten headroom.
	return source + 3*((child*5+3)/4) + (10 << 30), nil
}
func admitSpace(root, phase string, source, child uint64, publication bool) (SpaceCheck, error) {
	required, err := requiredSpace(source, child, publication)
	if err != nil {
		return SpaceCheck{}, err
	}
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return SpaceCheck{}, err
	}
	var available, total, free uint64
	if err = windows.GetDiskFreeSpaceEx(p, &available, &total, &free); err != nil {
		return SpaceCheck{}, errors.New("image volume free-space query failed")
	}
	r := SpaceCheck{Phase: phase, Available: available, Required: required, Source: source, Child: child}
	return r, r.check()
}
func (s SpaceCheck) check() error {
	if s.Available < s.Required {
		return fmt.Errorf("insufficient image volume space: available=%d required=%d source=%d child=%d bytes", s.Available, s.Required, s.Source, s.Child)
	}
	return nil
}
func diskSize(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 256<<30 {
		return 0, errors.New("image disk size unavailable or exceeds bound")
	}
	return uint64(info.Size()), nil // #nosec G115 -- checked positive and <=256 GiB above.
}

func finalPath(h windows.Handle) (string, error) {
	const size = 32768
	b := make([]uint16, size)
	n, err := windows.GetFinalPathNameByHandle(h, &b[0], size, 0)
	if err != nil || n == 0 || n >= size {
		return "", errors.New("cannot resolve final local input path")
	}
	p := strings.TrimPrefix(windows.UTF16ToString(b[:n]), `\\?\`)
	if !localPath(p) {
		return "", errors.New("final input path is not a bounded local path")
	}
	return p, nil
}
func disjointFinal(source, root string) error {
	if within(root, source) || within(filepath.Dir(source), root) {
		return errors.New("image root must be outside the ISO directory and its ancestors")
	}
	return nil
}

// Query-only handles: final path inspection never grants access or changes an
// ACL on the source, its parent, or the image root.
func checkFinalInputs(c Config) error {
	f, err := openReadOnlyPinned(c.ISO)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	source, err := finalPath(windows.Handle(f.Fd()))
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(c.ImageRoot)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return errors.New("cannot open image root for final path inspection")
	}
	defer func() { _ = windows.CloseHandle(h) }()
	root, err := finalPath(h)
	if err != nil {
		return err
	}
	return disjointFinal(source, root)
}

// Deny another reader/writer while allowing this holder's final RemoveAll to
// unlink the lock. Cleanup must open this same file before any native action.
func lockWorkspace(workspace string) (*os.File, error) {
	path := filepath.Join(workspace, "build.lock")
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_DELETE, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New("build workspace is locked by an active build or cleanup")
	}
	return os.NewFile(uintptr(h), path), nil
}
