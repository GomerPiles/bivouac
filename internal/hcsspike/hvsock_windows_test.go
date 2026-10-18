//go:build windows

package hcsspike

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"golang.org/x/sys/windows"
)

// A private loopback TCP fixture exercises the exact socket/OVERLAPPED ownership
// and cancellation path without HCS, a VM, a service registration or elevation.
func nativeSocketPair(t *testing.T) (*hvConn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	address := listener.Addr().(*net.TCPAddr)
	client, err := newHVSocket(windows.AF_INET, windows.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err = windows.Bind(client.socket, &windows.SockaddrInet4{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err = client.operation(ctx, &client.write, nil, func(o *hvOperation) error {
		return windows.ConnectEx(client.socket, &windows.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: address.Port}, nil, 0, &o.bytes, &o.overlapped)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.Setsockopt(client.socket, windows.SOL_SOCKET, windows.SO_UPDATE_CONNECT_CONTEXT, nil, 0); err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if err = server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestNativeSocketReadWriteAndEOF(t *testing.T) {
	client, server := nativeSocketPair(t)
	data := bytes.Repeat([]byte("synthetic"), 20000)
	done := make(chan error, 1)
	go func() { _, err := io.CopyN(server, server, int64(len(data))); done <- err }()
	if n, err := client.Write(data); err != nil || n != len(data) {
		t.Fatal("write failed", n, err)
	}
	actual := make([]byte, len(data))
	if _, err := io.ReadFull(client, actual); err != nil || !bytes.Equal(actual, data) {
		t.Fatal("stream changed", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	if n, err := client.Read(actual); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("EOF differs", n, err)
	}
}
func TestNativePendingOperationContextCancelsAndDrains(t *testing.T) {
	client, server := nativeSocketPair(t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	b := make([]byte, 16)
	start := time.Now()
	_, err := client.operation(ctx, &client.read, b, func(o *hvOperation) error {
		return windows.WSARecv(client.socket, &o.buffer, 1, &o.bytes, &o.flags, &o.overlapped, nil)
	})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal("pending native operation ignored cancellation", err)
	}
	// Reuse the same socket and direction after cancellation: no stale native read
	// may consume the next byte or write into the previous Go buffer.
	if _, err = server.Write([]byte{73}); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Read(b); n != 1 || err != nil || b[0] != 73 {
		t.Fatal("canceled I/O survived its caller", n, err)
	}
}
func TestNativeDeadlineChangesWakePendingRead(t *testing.T) {
	client, server := nativeSocketPair(t)
	done := make(chan error, 1)
	go func() { _, err := client.Read(make([]byte, 1)); done <- err }()
	if err := client.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline change did not wake read")
	}
	if err := client.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(client, b); err != nil || b[0] != 42 {
		t.Fatal("deadline reset failed", err)
	}
}
func TestNativeCloseJoinsConcurrentIO(t *testing.T) {
	client, _ := nativeSocketPair(t)
	if err := windows.SetsockoptInt(client.socket, windows.SOL_SOCKET, windows.SO_SNDBUF, 4096); err != nil {
		t.Fatal(err)
	}
	reads, writes := make(chan error, 1), make(chan error, 1)
	go func() { _, err := client.Read(make([]byte, 1)); reads <- err }()
	go func() { _, err := client.Write(make([]byte, 8<<20)); writes <- err }()
	// Explicit synchronization is unnecessary: Close must cover both operations
	// admitted before close and callers that only acquire their direction later.
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	for _, done := range []chan error{reads, writes} {
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
				t.Fatal("I/O survived close", err)
			}
		case <-time.After(time.Second):
			t.Fatal("close leaked native I/O")
		}
	}
	if err := client.Close(); err != nil {
		t.Fatal("repeated close failed", err)
	}
	if err := client.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("deadline accepted closed handle", err)
	}
}
func TestHVSocketCancelledBeforeCreation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if conn, err := dialHVSocket(ctx, nil); conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled dial allocated a transport", err)
	}
	if conn, err := dialHVSocket(t.Context(), nil); conn != nil || err == nil {
		t.Fatal("nil address accepted")
	}
}
func TestHVSocketNativeLoopbackRefusal(t *testing.T) {
	if os.Getenv("BIVOUAC_HVSOCK_NATIVE_TEST") != "1" {
		t.Skip("explicit host-only socket test; no HCS or VM")
	}
	id, err := guid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := dialHVSocket(ctx, &winio.HvsockAddr{VMID: winio.HvsockGUIDLoopback(), ServiceID: id})
	if conn != nil {
		_ = conn.Close()
		t.Fatal("unexpected listener on fresh random service")
	}
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("loopback refusal/cancellation exceeded bound", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, windows.WSAECONNREFUSED) && !errors.Is(err, windows.ERROR_CONNECTION_REFUSED) {
		t.Fatal("native socket setup failed before connect", err)
	}
}

func TestNativeCancellationBeforeWaitRegistration(t *testing.T) {
	client, _ := nativeSocketPair(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var submitted error
	_, err := client.operation(ctx, &client.read, make([]byte, 1), func(o *hvOperation) error {
		submitted = windows.WSARecv(client.socket, &o.buffer, 1, &o.bytes, &o.flags, &o.overlapped, nil)
		cancel() // Between kernel submission and cancellation callback registration.
		return submitted
	})
	if !errors.Is(submitted, windows.ERROR_IO_PENDING) {
		t.Fatal("fixture did not start pending I/O", submitted)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancel-before-wait lost", err)
	}
}
func TestNativeCloseDrainsAlreadyPendingOperation(t *testing.T) {
	client, _ := nativeSocketPair(t)
	issued, done := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := client.operation(t.Context(), &client.read, make([]byte, 1), func(o *hvOperation) error {
			err := windows.WSARecv(client.socket, &o.buffer, 1, &o.bytes, &o.flags, &o.overlapped, nil)
			issued <- err
			return err
		})
		done <- err
	}()
	if err := <-issued; !errors.Is(err, windows.ERROR_IO_PENDING) {
		t.Fatal("fixture did not start pending I/O", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
			t.Fatal("pending I/O survived close", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not drain pending operation")
	}
}
