package cachelink

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/streamrelay"
	"golang.org/x/sys/unix"
)

// Broker owns a fixed backend capability. Neither its protocol nor Dial can
// carry an address, path, command or bytes other than a one-byte open request.
// A relay (rather than an untracked duplicated backend FD) bounds and revokes
// every handed-out stream, including a compromised child's idle streams.
type Broker struct {
	control             *net.UnixConn
	payload, revocation brokerTarget
	ctx                 context.Context
	cancel              context.CancelFunc
	done                chan struct{}
	wg                  sync.WaitGroup
	once                sync.Once
}

func socketPair(kind int) (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, kind, 0)
	if err != nil {
		return nil, nil, err
	}
	for _, fd := range fds {
		unix.CloseOnExec(fd)
	}
	return os.NewFile(uintptr(fds[0]), "cache-owner"), os.NewFile(uintptr(fds[1]), "cache-child"), nil
}

type brokerTarget struct {
	path  string
	slots chan struct{}
}

func NewBroker(path, revocationPath string, limit int) (*Broker, *os.File, error) {
	if (path == "") != (revocationPath == "") {
		return nil, nil, errors.New("incomplete cache capabilities")
	}
	owner, child, err := socketPair(unix.SOCK_DGRAM)
	if err != nil {
		return nil, nil, err
	}
	c, err := net.FileConn(owner)
	_ = owner.Close()
	if err != nil {
		_ = child.Close()
		return nil, nil, err
	}
	if limit < 1 || limit > 65536 {
		_ = c.Close()
		_ = child.Close()
		return nil, nil, errors.New("invalid cache broker bound")
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Broker{control: c.(*net.UnixConn), payload: brokerTarget{path: path, slots: make(chan struct{}, limit)}, revocation: brokerTarget{path: revocationPath, slots: make(chan struct{}, MaxRevocationConnections)}, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	enabled := byte(0)
	if path != "" {
		enabled = 1
	}
	if _, err := b.control.Write([]byte{enabled}); err != nil {
		_ = child.Close()
		_ = b.control.Close()
		cancel()
		return nil, nil, err
	}
	go b.serve()
	return b, child, nil
}

func (b *Broker) Close() error {
	b.once.Do(func() { b.cancel(); _ = b.control.Close(); <-b.done; b.wg.Wait() })
	return nil
}
func (b *Broker) serve() {
	defer close(b.done)
	for {
		var request [2]byte
		ancillary := make([]byte, unix.CmsgSpace(16*4))
		n, oobn, flags, _, err := b.control.ReadMsgUnix(request[:], ancillary)
		// Always dispose of unsolicited capabilities, even on malformed requests.
		fds, valid := rights(ancillary[:oobn])
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		if err != nil {
			return
		}
		if n != 1 || (Kind(request[0]) != Payload && Kind(request[0]) != Revocation) || !valid || len(fds) != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			return
		}
		target := &b.payload
		if Kind(request[0]) == Revocation {
			target = &b.revocation
		}
		if target.path == "" {
			b.refuse()
			continue
		}
		select {
		case target.slots <- struct{}{}:
		default:
			b.refuse()
			continue
		}
		// Setup is serialized and bounded; the child cannot make the owner dial
		// anything except this VM's private cache listener.
		backend, err := (&net.Dialer{Timeout: time.Second}).DialContext(b.ctx, "unix", target.path)
		if err != nil {
			<-target.slots
			b.refuse()
			continue
		}
		owner, child, err := socketPair(unix.SOCK_STREAM)
		if err != nil {
			_ = backend.Close()
			<-target.slots
			b.refuse()
			continue
		}
		conn, err := net.FileConn(owner)
		_ = owner.Close()
		if err != nil {
			_ = child.Close()
			_ = backend.Close()
			<-target.slots
			b.refuse()
			continue
		}
		_, _, err = b.control.WriteMsgUnix([]byte{1}, unix.UnixRights(int(child.Fd())), nil)
		_ = child.Close()
		if err != nil {
			_ = conn.Close()
			_ = backend.Close()
			<-target.slots
			return
		}
		b.wg.Go(func() {
			defer func() { <-target.slots; _ = conn.Close(); _ = backend.Close() }()
			stop := context.AfterFunc(b.ctx, func() { _ = conn.Close(); _ = backend.Close() })
			defer stop()
			streamrelay.Copy(backend, conn)
		})
	}
}
func (b *Broker) refuse() { _, _ = b.control.Write([]byte{0}) }

// Client receives only connected Unix stream descriptors. A failed/ambiguous
// control exchange permanently disables caching for this child, not isolation.
type Client struct {
	control *net.UnixConn
	enabled bool
	mu      sync.Mutex
}

func NewClient(file *os.File) (*Client, error) {
	c, err := net.FileConn(file)
	if err != nil {
		return nil, errors.New("cache capability unavailable")
	}
	u, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		return nil, errors.New("invalid cache capability")
	}
	_ = u.SetReadDeadline(time.Now().Add(5 * time.Second))
	var msg [2]byte
	n, err := u.Read(msg[:])
	_ = u.SetReadDeadline(time.Time{})
	if err != nil || n != 1 || msg[0] > 1 {
		_ = u.Close()
		return nil, errors.New("cache capability handshake failed")
	}
	return &Client{control: u, enabled: msg[0] == 1}, nil
}
func (c *Client) Close() error  { return c.control.Close() }
func (c *Client) Enabled() bool { return c.enabled }
func (c *Client) Dial(ctx context.Context, kind Kind) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fail := func() (net.Conn, error) {
		_ = c.control.Close()
		return nil, errors.New("cache capability unavailable")
	}
	if !c.enabled || ctx.Err() != nil || (kind != Payload && kind != Revocation) {
		return nil, errors.New("cache unavailable")
	}
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if c.control.SetDeadline(deadline) != nil {
		return fail()
	}
	if _, err := c.control.Write([]byte{byte(kind)}); err != nil {
		return fail()
	}
	var msg [2]byte
	ancillary := make([]byte, unix.CmsgSpace(16*4))
	n, oobn, flags, _, err := c.control.ReadMsgUnix(msg[:], ancillary)
	fds, valid := rights(ancillary[:oobn])
	defer func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	if err != nil || !valid || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n != 1 {
		return fail()
	}
	if msg[0] == 0 && len(fds) == 0 {
		return nil, errors.New("cache busy or unavailable")
	}
	if msg[0] != 1 || len(fds) != 1 {
		return fail()
	}
	fd := fds[0]
	typ, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	addr, e2 := unix.Getpeername(fd)
	if _, ok := addr.(*unix.SockaddrUnix); !ok || e != nil || e2 != nil || typ != unix.SOCK_STREAM {
		return fail()
	}
	unix.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "cache-stream")
	fds = nil // os.File now owns it; net.FileConn duplicates it.
	conn, e := net.FileConn(f)
	_ = f.Close()
	if e != nil {
		return fail()
	}
	return conn, nil
}
func rights(data []byte) ([]int, bool) {
	messages, err := unix.ParseSocketControlMessage(data)
	if err != nil {
		return nil, false
	}
	var fds []int
	valid := true
	for _, m := range messages {
		if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SCM_RIGHTS {
			valid = false
			continue
		}
		values, err := unix.ParseUnixRights(&m)
		if err != nil {
			valid = false
		}
		fds = append(fds, values...)
	}
	return fds, valid
}
