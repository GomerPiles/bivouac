// Package engine carries opaque container API streams between disposable
// guests. Frames select a connection ID, never a host path or destination.
package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

const (
	openFrame      byte = 1
	dataFrame      byte = 2
	eofFrame       byte = 3
	closeFrame     byte = 4
	creditFrame    byte = 5
	maxFrame            = 32 << 10
	maxConnections      = 16
)

type frame struct {
	kind byte
	id   uint32
	data []byte
}

func readFrame(r io.Reader) (frame, error) {
	var h [9]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return frame{}, err
	}
	f := frame{kind: h[0], id: binary.BigEndian.Uint32(h[1:5])}
	n := binary.BigEndian.Uint32(h[5:])
	if f.id == 0 || f.kind < openFrame || f.kind > creditFrame || n > maxFrame || (f.kind != dataFrame && n != 0) || (f.kind == dataFrame && n == 0) {
		return frame{}, errors.New("invalid engine frame")
	}
	f.data = make([]byte, n)
	_, err := io.ReadFull(r, f.data)
	return f, err
}

type writer struct {
	mu  sync.Mutex
	out io.Writer
}

func (w *writer) send(f frame) error {
	n := len(f.data)
	if n > maxFrame {
		return errors.New("oversized engine frame")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var h [9]byte
	h[0] = f.kind
	binary.BigEndian.PutUint32(h[1:5], f.id)
	binary.BigEndian.PutUint32(h[5:], uint32(n))
	if _, err := io.Copy(w.out, bytes.NewReader(h[:])); err != nil {
		return err
	}
	_, err := io.Copy(w.out, bytes.NewReader(f.data))
	return err
}

type session struct {
	stream io.ReadWriteCloser
	w      writer
	mu     sync.Mutex
	active map[uint32]*channel
	wg     sync.WaitGroup
}
type channel struct {
	input   chan frame
	credits chan struct{}
	cancel  context.CancelFunc
}

func newSession(s io.ReadWriteCloser) *session {
	return &session{stream: s, w: writer{out: s}, active: make(map[uint32]*channel)}
}

func (s *session) attach(ctx context.Context, id uint32, dial func(context.Context) (net.Conn, error), announce bool) bool {
	s.mu.Lock()
	if len(s.active) >= maxConnections {
		s.mu.Unlock()
		return false
	}
	cctx, cancel := context.WithCancel(ctx)
	c := &channel{input: make(chan frame, 10), credits: make(chan struct{}, 8), cancel: cancel}
	for range 8 {
		c.credits <- struct{}{}
	}
	s.active[id] = c
	s.wg.Add(1)
	s.mu.Unlock()
	if announce {
		if err := s.w.send(frame{kind: openFrame, id: id}); err != nil {
			_ = s.stream.Close()
			cancel()
		}
	}
	go func() {
		defer s.wg.Done()
		defer cancel()
		defer func() {
			s.mu.Lock()
			delete(s.active, id)
			s.mu.Unlock()
			_ = s.w.send(frame{kind: closeFrame, id: id})
		}()
		conn, err := dial(cctx)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		stop := context.AfterFunc(cctx, func() { _ = conn.Close() })
		defer stop()
		readDone, readStopped := make(chan error, 1), make(chan struct{})
		go func() {
			defer close(readStopped)
			buf := make([]byte, maxFrame)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					select {
					case <-cctx.Done():
						readDone <- cctx.Err()
						return
					case <-c.credits:
					}
					if e := s.w.send(frame{kind: dataFrame, id: id, data: buf[:n]}); e != nil {
						_ = s.stream.Close()
						readDone <- e
						return
					}
				}
				if err != nil {
					if errors.Is(err, io.EOF) {
						err = s.w.send(frame{kind: eofFrame, id: id})
					}
					readDone <- err
					return
				}
			}
		}()
		// Wait for both halves, preserving HTTP upgrades and attach streams.
		defer func() {
			cancel()
			_ = conn.Close()
			<-readStopped
		}()
		readEOF, writeEOF := false, false
		for !readEOF || !writeEOF {
			select {
			case <-cctx.Done():
				return
			case err := <-readDone:
				readDone = nil
				if err != nil && !errors.Is(err, io.EOF) {
					return
				}
				readEOF = true
			case f := <-c.input:
				switch f.kind {
				case closeFrame:
					return
				case eofFrame:
					if writeEOF {
						return
					}
					writeEOF = true
					if half, ok := conn.(interface{ CloseWrite() error }); ok {
						if half.CloseWrite() != nil {
							return
						}
					} else {
						return
					}
				case dataFrame:
					if writeEOF {
						return
					}
					if _, err := io.Copy(conn, bytes.NewReader(f.data)); err != nil {
						return
					}
					if s.w.send(frame{kind: creditFrame, id: id}) != nil {
						_ = s.stream.Close()
						return
					}
				}
			}
		}
	}()
	return true
}

func (s *session) receive(f frame) {
	s.mu.Lock()
	c := s.active[f.id]
	s.mu.Unlock()
	if c == nil {
		return
	} // late close/data for a closed connection
	if f.kind == creditFrame {
		select {
		case c.credits <- struct{}{}:
		default:
			c.cancel()
		}
		return
	}
	select {
	case c.input <- f:
	default:
		c.cancel()
	} // one stalled client cannot grow host memory
}

func (s *session) close() {
	_ = s.stream.Close()
	s.mu.Lock()
	for _, c := range s.active {
		c.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// Relay serves frames from one guest and dials only the fixed per-job engine.
func Relay(ctx context.Context, stream io.ReadWriteCloser, dial func(context.Context) (net.Conn, error)) error {
	s := newSession(stream)
	defer s.close()
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	var lastID uint32
	for {
		f, err := readFrame(stream)
		if err != nil {
			return err
		}
		if f.kind == openFrame {
			if f.id <= lastID {
				return errors.New("reused engine connection ID")
			}
			lastID = f.id
			if !s.attach(ctx, f.id, dial, false) {
				if err := s.w.send(frame{kind: closeFrame, id: f.id}); err != nil {
					return err
				}
			}
		} else {
			s.receive(f)
		}
	}
}

// Listen exports a guest-local Unix socket over an attached VSOCK exec stream.
// Losing the stream closes the socket and every container API connection.
func Listen(ctx context.Context, stream io.ReadWriteCloser, listener net.Listener) error {
	s := newSession(stream)
	defer s.close()
	defer func() { _ = listener.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = stream.Close(); _ = listener.Close() })
	defer stop()
	errs := make(chan error, 1)
	go func() {
		for {
			f, err := readFrame(stream)
			if err != nil {
				errs <- err
				_ = listener.Close()
				return
			}
			if f.kind == openFrame {
				errs <- errors.New("unexpected engine open")
				_ = listener.Close()
				return
			}
			s.receive(f)
		}
	}()
	var id uint32
	for {
		conn, err := listener.Accept()
		if err != nil {
			_ = stream.Close()
			return <-errs
		}
		id++
		if id == 0 {
			_ = conn.Close()
			_ = stream.Close()
			return errors.New("engine connection IDs exhausted")
		}
		if !s.attach(ctx, id, func(context.Context) (net.Conn, error) { return conn, nil }, true) {
			_ = conn.Close()
		}
	}
}
