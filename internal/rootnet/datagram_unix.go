//go:build darwin || linux

package rootnet

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func readDatagram(c net.Conn, b []byte) (int, error) {
	if u, ok := c.(*net.UnixConn); ok {
		n, _, flags, _, err := u.ReadMsgUnix(b, nil)
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			return 0, errors.New("truncated isolated network frame")
		}
		return n, err
	}
	return c.Read(b)
}

// A connected UDP socket can be polled without borrowing a payload buffer.
// Non-socket connections are injected only by in-process stream fixtures.
func waitUDPReadable(c net.Conn) error {
	u, ok := c.(*net.UDPConn)
	if !ok {
		return nil
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return err
	}
	var readErr error
	err = raw.Read(func(fd uintptr) bool {
		var one [1]byte
		for {
			_, _, _, _, readErr = unix.Recvmsg(int(fd), one[:], nil, unix.MSG_PEEK|unix.MSG_DONTWAIT)
			if readErr != unix.EINTR {
				break
			}
		}
		return readErr != unix.EAGAIN && readErr != unix.EWOULDBLOCK
	})
	if err != nil {
		return err
	}
	return readErr
}
