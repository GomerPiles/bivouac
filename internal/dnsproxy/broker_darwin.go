package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

// The separate socket never delegates descriptors or accepts destinations.
// Correlation IDs allow bounded parallel queries without serializing cache/CRL.
const queryOp byte = 1
const cancelOp byte = 2
const responseOp byte = 3
const failedOp byte = 4
const envelopeSize = 9

type Broker struct {
	conn    *net.UnixConn
	ctx     context.Context
	cancel  context.CancelFunc
	resolve func(context.Context, []byte) ([]byte, error)
	mu      sync.Mutex
	pending map[uint64]context.CancelFunc
	limit   int
	done    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

func NewBroker(resolve func(context.Context, []byte) ([]byte, error), limit int) (*Broker, *os.File, error) {
	if limit < 1 || limit > 256 || resolve == nil {
		return nil, nil, errors.New("invalid DNS capability bound")
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, nil, err
	}
	for _, fd := range fds {
		unix.CloseOnExec(fd)
		for _, setting := range []struct{ option, size int }{{unix.SO_SNDBUF, 1 << 20}, {unix.SO_RCVBUF, 4 << 20}} {
			if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, setting.option, setting.size); err != nil {
				_ = unix.Close(fds[0])
				_ = unix.Close(fds[1])
				return nil, nil, err
			}
		}
	}
	owner := os.NewFile(uintptr(fds[0]), "dns-owner")
	child := os.NewFile(uintptr(fds[1]), "dns-child")
	conn, err := net.FileConn(owner)
	_ = owner.Close()
	if err != nil {
		_ = child.Close()
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Broker{conn: conn.(*net.UnixConn), ctx: ctx, cancel: cancel, resolve: resolve, pending: map[uint64]context.CancelFunc{}, limit: limit, done: make(chan struct{})}
	go b.serve()
	return b, child, nil
}
func (b *Broker) Close() error {
	b.once.Do(func() { b.cancel(); _ = b.conn.SetReadDeadline(time.Now()); <-b.done; b.wg.Wait(); _ = b.conn.Close() })
	return nil
}
func readMessage(c *net.UnixConn, buf []byte) (int, error) {
	ancillary := make([]byte, unix.CmsgSpace(64*4))
	n, oobn, flags, _, err := c.ReadMsgUnix(buf, ancillary)
	// Dispose of every unsolicited FD before rejecting ancillary data.
	if oobn > 0 {
		messages, _ := unix.ParseSocketControlMessage(ancillary[:oobn])
		for _, m := range messages {
			if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_RIGHTS {
				fds, _ := unix.ParseUnixRights(&m)
				for _, fd := range fds {
					_ = unix.Close(fd)
				}
			}
		}
	}
	if err != nil {
		return 0, err
	}
	if oobn != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n < envelopeSize {
		return 0, errors.New("invalid DNS capability message")
	}
	return n, nil
}
func message(op byte, id uint64, data []byte) []byte {
	b := make([]byte, envelopeSize+len(data))
	b[0] = op
	binary.BigEndian.PutUint64(b[1:9], id)
	copy(b[9:], data)
	return b
}
func (b *Broker) send(op byte, id uint64, data []byte) {
	_ = b.conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = b.conn.Write(message(op, id, data))
}
func (b *Broker) serve() {
	defer close(b.done)
	for {
		buf := make([]byte, MaxQuery+envelopeSize)
		n, err := readMessage(b.conn, buf)
		if err != nil {
			return
		}
		id := binary.BigEndian.Uint64(buf[1:9])
		if id == 0 {
			return
		}
		if buf[0] == cancelOp && n == envelopeSize {
			b.mu.Lock()
			cancel := b.pending[id]
			b.mu.Unlock()
			if cancel != nil {
				cancel()
			}
			continue
		}
		if buf[0] != queryOp {
			return
		}
		q, query, err := Query(buf[9:n])
		if errors.Is(err, BadVersion) {
			b.send(responseOp, id, Failure(q, dns.RcodeBadVers))
			continue
		}
		if err != nil {
			b.send(failedOp, id, nil)
			continue
		}
		b.mu.Lock()
		_, duplicate := b.pending[id]
		if duplicate || len(b.pending) >= b.limit {
			b.mu.Unlock()
			b.send(failedOp, id, nil)
			continue
		}
		ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
		b.pending[id] = cancel
		b.mu.Unlock()
		b.wg.Go(func() {
			defer cancel()
			defer func() { b.mu.Lock(); delete(b.pending, id); b.mu.Unlock() }()
			response, err := b.resolve(ctx, query)
			if ctx.Err() != nil || err != nil || len(response) > MaxResponse {
				b.send(failedOp, id, nil)
				return
			}
			q, _, _ := Query(query)
			if _, err := ValidateResponse(response, q); err != nil {
				b.send(failedOp, id, nil)
				return
			}
			b.send(responseOp, id, response)
		})
	}
}

type reply struct {
	data []byte
	err  error
}
type Client struct {
	conn    *net.UnixConn
	mu      sync.Mutex
	pending map[uint64]chan reply
	next    atomic.Uint64
	done    chan struct{}
	once    sync.Once
	closed  bool
	limit   int
}

func NewClient(file *os.File, limit int) (*Client, error) {
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, errors.New("DNS capability unavailable")
	}
	u, ok := conn.(*net.UnixConn)
	if !ok || limit < 1 || limit > 256 {
		_ = conn.Close()
		return nil, errors.New("invalid DNS capability")
	}
	c := &Client{conn: u, pending: map[uint64]chan reply{}, done: make(chan struct{}), limit: limit}
	go c.read()
	return c, nil
}
func (c *Client) Close() error { c.once.Do(func() { _ = c.conn.Close(); <-c.done }); return nil }
func (c *Client) read() {
	defer close(c.done)
	defer func() {
		c.mu.Lock()
		c.closed = true
		for _, ch := range c.pending {
			select {
			case ch <- reply{err: errors.New("DNS capability lost")}:
			default:
			}
		}
		c.mu.Unlock()
	}()
	buf := make([]byte, MaxResponse+envelopeSize)
	for {
		n, err := readMessage(c.conn, buf)
		if err != nil {
			return
		}
		id := binary.BigEndian.Uint64(buf[1:9])
		if buf[0] != responseOp && buf[0] != failedOp {
			return
		}
		r := reply{data: append([]byte(nil), buf[9:n]...)}
		if buf[0] == failedOp {
			r.err = errors.New("DNS unavailable")
		}
		c.mu.Lock()
		ch := c.pending[id]
		if ch != nil {
			select {
			case ch <- r:
			default:
			}
		}
		c.mu.Unlock()
	}
}
func (c *Client) Resolve(parent context.Context, raw []byte) ([]byte, error) {
	q, query, err := Query(raw)
	if errors.Is(err, BadVersion) {
		return Failure(q, dns.RcodeBadVers), nil
	}
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	ch := make(chan reply, 1)
	id := c.next.Add(1)
	c.mu.Lock()
	if c.closed || len(c.pending) >= c.limit {
		c.mu.Unlock()
		return nil, errors.New("DNS capability busy")
	}
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, id); c.mu.Unlock() }()
	_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := c.conn.Write(message(queryOp, id, query)); err != nil {
		return nil, errors.New("DNS capability unavailable")
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if _, err := ValidateResponse(r.data, q); err != nil {
			return nil, err
		}
		return r.data, nil
	case <-ctx.Done():
		_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = c.conn.Write(message(cancelOp, id, nil))
		return nil, errors.New("DNS query ended")
	}
}
