//go:build darwin || linux

package guestagent

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// vsockListener accepts vsock streams through the runtime poller. The net
// package does not know AF_VSOCK, so descriptors are wrapped in os.File.
type vsockListener struct{ f *os.File }

func listen(port uint32) (Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Listen(fd, 16); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &vsockListener{f: os.NewFile(uintptr(fd), "vsock-listener")}, nil
}

// Accept returns the next connection from the host; connections from any
// other context ID (such as a local loopback peer) are closed unanswered.
func (l *vsockListener) Accept() (io.ReadWriteCloser, error) {
	raw, err := l.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	for {
		var nfd int
		var peer unix.Sockaddr
		var acceptErr error
		err := raw.Read(func(fd uintptr) bool {
			nfd, peer, acceptErr = unix.Accept(int(fd))
			return !errors.Is(acceptErr, unix.EAGAIN)
		})
		if err != nil {
			return nil, err
		}
		if acceptErr != nil {
			if errors.Is(acceptErr, unix.ECONNABORTED) || errors.Is(acceptErr, unix.EINTR) {
				continue
			}
			return nil, acceptErr
		}
		vm, ok := peer.(*unix.SockaddrVM)
		if !ok || vm.CID != unix.VMADDR_CID_HOST {
			_ = unix.Close(nfd)
			continue
		}
		unix.CloseOnExec(nfd)
		if err := unix.SetNonblock(nfd, true); err != nil {
			_ = unix.Close(nfd)
			return nil, err
		}
		return os.NewFile(uintptr(nfd), "vsock"), nil
	}
}

func (l *vsockListener) Close() error { return l.f.Close() }
