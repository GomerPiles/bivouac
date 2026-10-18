//go:build windows

package hcsspike

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"golang.org/x/sys/windows"
)

// hvConn owns its socket, Winsock reference, DLL reference and wait events.
// Event-based overlapped I/O avoids depending on go-winio's non-cancellable
// ConnectEx wait. No native operation or Go buffer outlives its caller: every
// cancellation requests CancelIoEx and drains completion before releasing pins.
type hvConn struct {
	mu                 sync.Mutex
	socket             windows.Handle
	dll                windows.Handle
	bindProc, nameProc uintptr
	closed             bool
	closeDone          chan struct{}
	closeErr           error
	active             sync.WaitGroup
	read, write        hvDirection
	local, remote      net.Addr
}
type hvDirection struct {
	serial   sync.Mutex
	wake     windows.Handle // auto-reset; also wakes a pending wait after deadline changes
	deadline time.Time      // protected by hvConn.mu
}
type hvOperation struct {
	overlapped   windows.Overlapped
	bytes, flags uint32
	buffer       windows.WSABuf
	address      rawHVAddress
}
type rawHVAddress struct {
	Family, Reserved uint16
	VMID, ServiceID  guid.GUID
}

func newHVSocket(family, protocol int32) (_ *hvConn, err error) {
	var data windows.WSAData
	if err = windows.WSAStartup(0x202, &data); err != nil {
		return nil, err
	}
	c := &hvConn{socket: windows.InvalidHandle, closeDone: make(chan struct{})}
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

func dialHVSocket(ctx context.Context, address *winio.HvsockAddr) (_ net.Conn, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if address == nil {
		return nil, errors.New("missing HvSocket address")
	}
	c, err := newHVSocket(34, 1) // AF_HYPERV, HV_PROTOCOL_RAW
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = c.Close()
		}
	}()
	local := rawHVAddress{Family: 34}
	r, _, callErr := syscall.SyscallN(c.bindProc, uintptr(c.socket), uintptr(unsafe.Pointer(&local)), unsafe.Sizeof(local)) // #nosec G103 -- fixed SOCKADDR_HV passed only during bind.
	runtime.KeepAlive(&local)
	if uint32(r) == ^uint32(0) {
		return nil, callErr
	} // #nosec G115 -- SOCKET_ERROR is the low 32 bits.
	id := windows.GUID{Data1: 0x25a207b9, Data2: 0xddf3, Data3: 0x4660, Data4: [8]byte{0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e}}
	var connect uintptr
	var returned uint32
	if err = windows.WSAIoctl(c.socket, windows.SIO_GET_EXTENSION_FUNCTION_POINTER,
		(*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id)), (*byte)(unsafe.Pointer(&connect)), uint32(unsafe.Sizeof(connect)), &returned, nil, 0); err != nil {
		return nil, err
	} // #nosec G103 -- documented GUID/function-pointer output buffers.
	if connect == 0 || returned != uint32(unsafe.Sizeof(connect)) {
		return nil, errors.New("ConnectEx pointer unavailable")
	}
	c.remote = &winio.HvsockAddr{VMID: address.VMID, ServiceID: address.ServiceID}
	_, err = c.operation(ctx, &c.write, nil, func(o *hvOperation) error {
		o.address = rawHVAddress{Family: 34, VMID: address.VMID, ServiceID: address.ServiceID}
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
	if uint32(r) == ^uint32(0) || n != int32(unsafe.Sizeof(local)) || local.Family != 34 {
		return nil, errors.Join(errors.New("HvSocket local address unavailable"), callErr)
	} // #nosec G115 -- SOCKET_ERROR is the low 32 bits.
	c.local = &winio.HvsockAddr{VMID: local.VMID, ServiceID: local.ServiceID}
	return c, nil
}

// operation holds native buffer pins until completion, including cancellation.
// The issue call and close/cancel admission share mu, preventing cancel-before-
// issue races. WaitForMultipleObjects wakes on I/O, context, close or deadlines.
func (c *hvConn) operation(ctx context.Context, direction *hvDirection, b []byte, issue func(*hvOperation) error) (int, error) {
	o := new(hvOperation)
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
		o.buffer = windows.WSABuf{Buf: &b[0], Len: uint32(len(b))}
	} // #nosec G115 -- callers cap buffers at 64 KiB.
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
	if !direction.deadline.IsZero() && !time.Now().Before(direction.deadline) {
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
			_ = windows.SetEvent(direction.wake)
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
		closed, deadline := c.closed, direction.deadline
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
				timeout = uint32(ms)
			} // #nosec G115 -- positive value strictly below INFINITE.
		}
		result, waitErr := windows.WaitForMultipleObjects([]windows.Handle{event, direction.wake}, false, timeout)
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
func (c *hvConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.read.serial.Lock()
	defer c.read.serial.Unlock()
	if len(b) > 64<<10 {
		b = b[:64<<10]
	}
	n, err := c.operation(context.Background(), &c.read, b, func(o *hvOperation) error {
		return windows.WSARecv(c.socket, &o.buffer, 1, &o.bytes, &o.flags, &o.overlapped, nil)
	})
	if n == 0 && err == nil {
		err = io.EOF
	}
	return n, err
}
func (c *hvConn) Write(b []byte) (int, error) {
	c.write.serial.Lock()
	defer c.write.serial.Unlock()
	total := 0
	for len(b) > 0 {
		part := b
		if len(part) > 64<<10 {
			part = part[:64<<10]
		}
		n, err := c.operation(context.Background(), &c.write, part, func(o *hvOperation) error {
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
func (c *hvConn) Close() error {
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
func (c *hvConn) LocalAddr() net.Addr           { return c.local }
func (c *hvConn) RemoteAddr() net.Addr          { return c.remote }
func (c *hvConn) SetDeadline(t time.Time) error { return c.setDeadlines(t, t, true, true) }
func (c *hvConn) SetReadDeadline(t time.Time) error {
	return c.setDeadlines(t, time.Time{}, true, false)
}
func (c *hvConn) SetWriteDeadline(t time.Time) error {
	return c.setDeadlines(time.Time{}, t, false, true)
}
func (c *hvConn) setDeadlines(read, write time.Time, setRead, setWrite bool) error {
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
