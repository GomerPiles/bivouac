//go:build windows

// Package hvsock dials Hyper-V sockets (AF_HYPERV) with cancellable,
// deadline-aware overlapped I/O.
//
// go-winio's dialer waits on ConnectEx without observing its context. A guest
// service that is not yet listening leaves that connect pending for about 30
// seconds, which held readiness hostage in live trials. Here every operation
// waits on its own event together with a wake event signalled by context,
// deadline and close changes. Cancellation requests CancelIoEx and drains
// completion before releasing pinned buffers, events or the socket.
package hvsock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	afHyperV      = 34
	protocolRaw   = 1
	maxTransferIO = 64 << 10
)

// Addr is a Hyper-V socket address: a partition (VM runtime) ID and a service ID.
type Addr struct {
	VMID, ServiceID windows.GUID
}

func (Addr) Network() string  { return "hvsock" }
func (a Addr) String() string { return a.VMID.String() + ":" + a.ServiceID.String() }

// ParseGUID accepts the brace-less form HCS reports, or the braced form.
func ParseGUID(text string) (windows.GUID, error) {
	if !strings.HasPrefix(text, "{") {
		text = "{" + text + "}"
	}
	id, err := windows.GUIDFromString(text)
	if err != nil {
		return windows.GUID{}, fmt.Errorf("invalid GUID: %w", err)
	}
	return id, nil
}

// LoopbackVMID addresses services on the local partition.
func LoopbackVMID() windows.GUID {
	return windows.GUID{Data1: 0xe0e16197, Data2: 0xdd56, Data3: 0x4a10, Data4: [8]byte{0x91, 0x95, 0x5e, 0xe7, 0xa1, 0x55, 0xa8, 0x38}}
}

// conn owns its socket, Winsock reference, DLL reference and wait events.
// No native operation or Go buffer outlives its caller.
type conn struct {
	mu                 sync.Mutex
	socket             windows.Handle
	dll                windows.Handle
	bindProc, nameProc uintptr
	closed             bool
	closeDone          chan struct{}
	closeErr           error
	active             sync.WaitGroup
	read, write        direction
	local, remote      net.Addr
}
type direction struct {
	serial   sync.Mutex
	wake     windows.Handle // auto-reset; also wakes a pending wait after deadline changes
	deadline time.Time      // protected by conn.mu
}
type operation struct {
	overlapped   windows.Overlapped
	bytes, flags uint32
	buffer       windows.WSABuf
	address      rawAddr
}
type rawAddr struct {
	Family, Reserved uint16
	VMID, ServiceID  windows.GUID
}

func newSocket(family, protocol int32) (_ *conn, err error) {
	var data windows.WSAData
	if err = windows.WSAStartup(0x202, &data); err != nil {
		return nil, err
	}
	c := &conn{socket: windows.InvalidHandle, closeDone: make(chan struct{})}
	defer func() {
		if err != nil {
			_ = c.Close()
		}
	}()
	c.dll, err = windows.LoadLibraryEx("ws2_32.dll", 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, err
	}
	c.bindProc, err = windows.GetProcAddress(c.dll, "bind")
	if err != nil {
		return nil, err
	}
	c.nameProc, err = windows.GetProcAddress(c.dll, "getsockname")
	if err != nil {
		return nil, err
	}
	c.socket, err = windows.WSASocket(family, windows.SOCK_STREAM, protocol, nil, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		return nil, err
	}
	c.read.wake, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	c.write.wake, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Dial connects within ctx. A refused or absent service fails; the caller
// decides whether and how soon to retry.
func Dial(ctx context.Context, address Addr) (_ net.Conn, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	c, err := newSocket(afHyperV, protocolRaw)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = c.Close()
		}
	}()
	local := rawAddr{Family: afHyperV}
	r, _, callErr := syscall.SyscallN(c.bindProc, uintptr(c.socket), uintptr(unsafe.Pointer(&local)), unsafe.Sizeof(local)) // #nosec G103 -- fixed SOCKADDR_HV passed only during bind.
	runtime.KeepAlive(&local)
	if uint32(r&0xffffffff) == ^uint32(0) {
		return nil, callErr
	}
	connectExID := windows.GUID{Data1: 0x25a207b9, Data2: 0xddf3, Data3: 0x4660, Data4: [8]byte{0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e}}
	var connect uintptr
	var returned uint32
	if err = windows.WSAIoctl(c.socket, windows.SIO_GET_EXTENSION_FUNCTION_POINTER,
		(*byte)(unsafe.Pointer(&connectExID)), uint32(unsafe.Sizeof(connectExID)), (*byte)(unsafe.Pointer(&connect)), uint32(unsafe.Sizeof(connect)), &returned, nil, 0); err != nil { // #nosec G103 -- documented GUID/function-pointer output buffers.
		return nil, err
	}
	if connect == 0 || returned != uint32(unsafe.Sizeof(connect)) {
		return nil, errors.New("ConnectEx pointer unavailable")
	}
	c.remote = address
	_, err = c.operation(ctx, &c.write, nil, func(o *operation) error {
		o.address = rawAddr{Family: afHyperV, VMID: address.VMID, ServiceID: address.ServiceID}
		ok, _, e := syscall.SyscallN(connect, uintptr(c.socket), uintptr(unsafe.Pointer(&o.address)), unsafe.Sizeof(o.address), 0, 0, uintptr(unsafe.Pointer(&o.bytes)), uintptr(unsafe.Pointer(&o.overlapped))) // #nosec G103 -- pinned native buffers remain alive until ConnectEx completion.
		if ok == 0 {
			if e == 0 {
				return windows.WSAEINVAL
			}
			return e
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = windows.Setsockopt(c.socket, windows.SOL_SOCKET, windows.SO_UPDATE_CONNECT_CONTEXT, nil, 0); err != nil {
		return nil, err
	}
	n := int32(unsafe.Sizeof(local))
	r, _, callErr = syscall.SyscallN(c.nameProc, uintptr(c.socket), uintptr(unsafe.Pointer(&local)), uintptr(unsafe.Pointer(&n))) // #nosec G103 -- fixed bounded SOCKADDR_HV output.
	runtime.KeepAlive(&local)
	if uint32(r&0xffffffff) == ^uint32(0) || n != int32(unsafe.Sizeof(local)) || local.Family != afHyperV {
		return nil, errors.Join(errors.New("HvSocket local address unavailable"), callErr)
	}
	c.local = Addr{VMID: local.VMID, ServiceID: local.ServiceID}
	return c, nil
}

// operation holds native buffer pins until completion, including cancellation.
// The issue call and close/cancel admission share mu, preventing cancel-before-
// issue races. WaitForMultipleObjects wakes on I/O, context, close or deadlines.
func (c *conn) operation(ctx context.Context, d *direction, b []byte, issue func(*operation) error) (int, error) {
	o := new(operation)
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(event) }()
	o.overlapped.HEvent = event
	var pins runtime.Pinner
	pins.Pin(o)
	if len(b) != 0 {
		pins.Pin(&b[0])
		o.buffer = windows.WSABuf{Buf: &b[0], Len: uint32(len(b))} // #nosec G115 -- callers cap buffers at maxTransferIO.
	}
	defer pins.Unpin()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if err = ctx.Err(); err != nil {
		c.mu.Unlock()
		return 0, err
	}
	if !d.deadline.IsZero() && !time.Now().Before(d.deadline) {
		c.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	c.active.Add(1)
	err = issue(o)
	c.mu.Unlock()
	defer c.active.Done()
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return int(o.bytes), err
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		c.mu.Lock()
		if !c.closed {
			_ = windows.SetEvent(d.wake)
		}
		c.mu.Unlock()
		close(callbackDone)
	})
	defer func() {
		if !stop() {
			<-callbackDone
		}
	}()
	drain := func(reason error) (int, error) {
		_ = windows.CancelIoEx(c.socket, &o.overlapped)
		_ = windows.WSAGetOverlappedResult(c.socket, &o.overlapped, &o.bytes, true, &o.flags)
		return int(o.bytes), reason
	}
	for {
		c.mu.Lock()
		closed, deadline := c.closed, d.deadline
		c.mu.Unlock()
		if closed {
			return drain(net.ErrClosed)
		}
		if err = ctx.Err(); err != nil {
			return drain(err)
		}
		timeout := uint32(windows.INFINITE)
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return drain(os.ErrDeadlineExceeded)
			}
			ms := (remaining + time.Millisecond - 1) / time.Millisecond
			if ms < time.Duration(windows.INFINITE) {
				timeout = uint32(ms) // #nosec G115 -- positive value strictly below INFINITE.
			}
		}
		result, waitErr := windows.WaitForMultipleObjects([]windows.Handle{event, d.wake}, false, timeout)
		if waitErr != nil {
			return drain(waitErr)
		}
		if result == windows.WAIT_OBJECT_0 {
			err = windows.WSAGetOverlappedResult(c.socket, &o.overlapped, &o.bytes, false, &o.flags)
			return int(o.bytes), err
		}
		if result != windows.WAIT_OBJECT_0+1 && result != uint32(windows.WAIT_TIMEOUT) {
			return drain(errors.New("unexpected socket wait result"))
		}
	}
}
func (c *conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.read.serial.Lock()
	defer c.read.serial.Unlock()
	if len(b) > maxTransferIO {
		b = b[:maxTransferIO]
	}
	n, err := c.operation(context.Background(), &c.read, b, func(o *operation) error {
		return windows.WSARecv(c.socket, &o.buffer, 1, &o.bytes, &o.flags, &o.overlapped, nil)
	})
	if n == 0 && err == nil {
		err = io.EOF
	}
	return n, err
}
func (c *conn) Write(b []byte) (int, error) {
	c.write.serial.Lock()
	defer c.write.serial.Unlock()
	total := 0
	for len(b) > 0 {
		part := b
		if len(part) > maxTransferIO {
			part = part[:maxTransferIO]
		}
		n, err := c.operation(context.Background(), &c.write, part, func(o *operation) error {
			return windows.WSASend(c.socket, &o.buffer, 1, &o.bytes, 0, &o.overlapped, nil)
		})
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
		b = b[n:]
	}
	return total, nil
}
func (c *conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		<-c.closeDone
		return c.closeErr
	}
	c.closed = true
	if c.socket != windows.InvalidHandle {
		_ = windows.CancelIoEx(c.socket, nil)
	}
	for _, event := range []windows.Handle{c.read.wake, c.write.wake} {
		if event != 0 {
			_ = windows.SetEvent(event)
		}
	}
	c.mu.Unlock()
	c.active.Wait()
	if c.socket != windows.InvalidHandle {
		c.closeErr = windows.Closesocket(c.socket)
	}
	for _, event := range []windows.Handle{c.read.wake, c.write.wake} {
		if event != 0 {
			c.closeErr = errors.Join(c.closeErr, windows.CloseHandle(event))
		}
	}
	if c.dll != 0 {
		c.closeErr = errors.Join(c.closeErr, windows.FreeLibrary(c.dll))
	}
	c.closeErr = errors.Join(c.closeErr, windows.WSACleanup())
	close(c.closeDone)
	return c.closeErr
}
func (c *conn) LocalAddr() net.Addr           { return c.local }
func (c *conn) RemoteAddr() net.Addr          { return c.remote }
func (c *conn) SetDeadline(t time.Time) error { return c.setDeadlines(t, t, true, true) }
func (c *conn) SetReadDeadline(t time.Time) error {
	return c.setDeadlines(t, time.Time{}, true, false)
}
func (c *conn) SetWriteDeadline(t time.Time) error {
	return c.setDeadlines(time.Time{}, t, false, true)
}
func (c *conn) setDeadlines(read, write time.Time, setRead, setWrite bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if setRead {
		c.read.deadline = read
		if err := windows.SetEvent(c.read.wake); err != nil {
			return err
		}
	}
	if setWrite {
		c.write.deadline = write
		if err := windows.SetEvent(c.write.wake); err != nil {
			return err
		}
	}
	return nil
}
