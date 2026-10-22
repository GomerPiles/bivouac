//go:build windows

package guestagent

import "io"

// LockGuestDirectory pins and verifies the receiver's protected directory and
// serializes adapter preparation/launch with delivery. The caller must retain
// the returned guard until all file publication (including launched) finishes.
// No guest command can select another directory.
func LockGuestDirectory() (io.Closer, error) {
	d, err := openGuestDirectory(guestDirectory)
	if err != nil {
		return nil, err
	}
	lock, err := d.lock()
	if err != nil {
		d.Close()
		return nil, err
	}
	return &guestFilesGuard{directory: d, lock: lock}, nil
}

type guestFilesGuard struct {
	directory *guestDir
	lock      io.Closer
}

func (g *guestFilesGuard) Close() error {
	err := g.lock.Close()
	g.directory.Close()
	return err
}
