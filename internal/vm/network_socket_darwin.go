package vm

import (
	"bytes"
	"errors"

	"golang.org/x/sys/unix"
)

func networkSocketpair(mtu int) ([2]int, error) {
	var empty [2]int
	if mtu < 1500 || mtu > 65535 {
		return empty, errors.New("invalid isolated network MTU")
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return empty, err
	}
	good := false
	defer func() {
		if !good {
			_ = unix.Close(fds[0])
			_ = unix.Close(fds[1])
		}
	}()
	for _, fd := range fds {
		unix.CloseOnExec(fd)
		for _, setting := range []struct{ option, size int }{{unix.SO_SNDBUF, 1 << 20}, {unix.SO_RCVBUF, 4 << 20}} {
			if unix.SetsockoptInt(fd, unix.SOL_SOCKET, setting.option, setting.size) != nil {
				return empty, errors.New("isolated network socket buffer setup failed")
			}
		}
		send, e1 := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
		receive, e2 := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
		if e1 != nil || e2 != nil || send < 1<<20 || receive < 4*send {
			return empty, errors.New("isolated network socket buffer size unproven")
		}
	}
	// A readback alone does not prove maxdgram behavior. Exchange and drain one
	// full Ethernet frame in each direction before handing either FD to VZ.
	frame := bytes.Repeat([]byte{0xa5}, mtu+14)
	buf := make([]byte, len(frame)+1)
	for i, fd := range fds {
		n, err := unix.Write(fd, frame)
		if err != nil || n != len(frame) {
			return empty, errors.New("full-MTU datagram send unproven")
		}
		n, _, flags, _, err := unix.Recvmsg(fds[1-i], buf, nil, unix.MSG_DONTWAIT)
		if err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n != len(frame) || !bytes.Equal(buf[:n], frame) {
			return empty, errors.New("full-MTU datagram receive unproven")
		}
	}
	good = true
	return fds, nil
}
