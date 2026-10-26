package vm

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestAttachmentSocketBuffersAdmitFullMTU(t *testing.T) {
	for _, mtu := range []int{1500, 9000, 65535} {
		fds, err := networkSocketpair(mtu)
		if err != nil {
			t.Fatalf("MTU %d buffer proof failed: %v", mtu, err)
		}
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	}
}
