package streamrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	a, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.Accept()
	if err != nil {
		_ = a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	return a.(*net.TCPConn), b.(*net.TCPConn)
}
func TestEOFHalfCloseBothDirections(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "a", true: "b"}[reverse], func(t *testing.T) {
			a, ar := tcpPair(t)
			b, br := tcpPair(t)
			done := make(chan struct{})
			go func() { defer close(done); Copy(ar, br) }()
			if reverse {
				a, b = b, a
			}
			if _, err := io.WriteString(a, "before"); err != nil {
				t.Fatal(err)
			}
			if err := a.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(b)
			if err != nil || string(data) != "before" {
				t.Fatal("EOF not propagated", err)
			}
			select {
			case <-done:
				t.Fatal("relay ended at first EOF")
			default:
			}
			if _, err := io.WriteString(b, "after"); err != nil {
				t.Fatal(err)
			}
			if err := b.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			data, err = io.ReadAll(a)
			if err != nil || string(data) != "after" {
				t.Fatal("half-close lost opposite data", err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("relay did not join both directions")
			}
		})
	}
}

type errorConn struct{ net.Conn }

func (errorConn) Read([]byte) (int, error) { return 0, errors.New("fixture read failure") }
func TestErrorClosesBothDirections(t *testing.T) {
	a, ar := net.Pipe()
	b, br := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	done := make(chan struct{})
	go func() { defer close(done); Copy(errorConn{ar}, br) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("error did not unblock other copy")
	}
	for _, c := range []net.Conn{a, b} {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("error left stream open")
		}
	}
}
func TestOwnerCancellationClosesAndJoins(t *testing.T) {
	a, ar := net.Pipe()
	b, br := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, func() { _ = ar.Close(); _ = br.Close() })
	defer stop()
	done := make(chan struct{})
	go func() { defer close(done); Copy(ar, br) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled owner left relay goroutine")
	}
}
