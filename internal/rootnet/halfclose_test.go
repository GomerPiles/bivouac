package rootnet

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestPublicTCPHalfClose(t *testing.T) {
	for _, serverFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "upstream", false: "guest"}[serverFirst], func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			result := make(chan error, 1)
			go func() {
				c, err := listener.Accept()
				if err != nil {
					result <- err
					return
				}
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if serverFirst {
					_, err = io.WriteString(c, "hello")
					if err == nil {
						err = c.(*net.TCPConn).CloseWrite()
					}
				}
				if err == nil {
					var b []byte
					b, err = io.ReadAll(c)
					if err == nil && string(b) != "after" {
						err = io.ErrUnexpectedEOF
					}
				}
				if !serverFirst && err == nil {
					_, err = io.WriteString(c, "hello")
					if err == nil {
						err = c.(*net.TCPConn).CloseWrite()
					}
				}
				result <- err
			}()
			n, err := newNetwork(context.Background(), testMAC, options{allow: func(netip.Addr) bool { return true }, dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
			}})
			if err != nil {
				t.Fatal(err)
			}
			s, ctx := guestStack(t, n)
			c, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 443}, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if !serverFirst {
				_, err = io.WriteString(c, "after")
				if err == nil {
					err = c.CloseWrite()
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			b, err := io.ReadAll(c)
			if err != nil || string(b) != "hello" {
				t.Fatalf("read after half-close: %q %v", b, err)
			}
			if serverFirst {
				_, err = io.WriteString(c, "after")
				if err == nil {
					err = c.CloseWrite()
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := <-result; err != nil {
				t.Fatal("server did not receive after half-close:", err)
			}
		})
	}
}
