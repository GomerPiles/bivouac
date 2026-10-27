//go:build !darwin && !linux

package rootnet

import (
	"net"
	"testing"
)

func socketFixture(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	t.Skip("native datagram attachment unavailable")
	return nil, nil
}
