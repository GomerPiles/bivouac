//go:build darwin || linux

package rootnet

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func socketFixture(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	var conns [2]net.Conn
	for i, fd := range fds {
		for _, setting := range []struct{ option, size int }{{unix.SO_SNDBUF, 1 << 20}, {unix.SO_RCVBUF, 4 << 20}} {
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, setting.option, setting.size); err != nil {
				t.Fatal(err)
			}
		}
		f := os.NewFile(uintptr(fd), "fixture")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c
	}
	return conns[0], conns[1]
}
