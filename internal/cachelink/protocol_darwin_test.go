package cachelink

import (
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestBrokerRejectsMalformedRequestsAndUnsolicitedDescriptors(t *testing.T) {
	for _, kind := range []string{"unknown", "oversized", "descriptor"} {
		t.Run(kind, func(t *testing.T) {
			broker, fd, err := NewBroker("", "", 32)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = broker.Close() }()
			defer func() { _ = fd.Close() }()
			conn, err := net.FileConn(fd)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			control := conn.(*net.UnixConn)
			var initial [1]byte
			if _, err := control.Read(initial[:]); err != nil {
				t.Fatal(err)
			}
			data := []byte{255}
			var ancillary []byte
			if kind == "oversized" {
				data = []byte{1, 0, 0}
			}
			if kind == "descriptor" {
				data = []byte{1}
				file, err := os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = file.Close() }()
				ancillary = unix.UnixRights(int(file.Fd()))
			}
			if _, _, err := control.WriteMsgUnix(data, ancillary, nil); err != nil {
				t.Fatal(err)
			}
			select {
			case <-broker.done:
			case <-time.After(time.Second):
				t.Fatal("malformed cache request was not terminal")
			}
		})
	}
}
