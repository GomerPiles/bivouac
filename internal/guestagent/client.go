package guestagent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Dialer opens one raw connection to a guest agent.
type Dialer func(ctx context.Context) (net.Conn, error)

// DialUnix reaches a guest agent through its VM helper's socket.
func DialUnix(path string) Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}
}

// ErrUnavailable reports that the agent could not be reached or the
// connection ended before the command's exit status arrived.
var ErrUnavailable = errors.New("guest agent unavailable")

// ErrNotStarted reports that the agent refused or failed to start the command.
var ErrNotStarted = errors.New("guest agent could not start the command")

// ExitError is a command that ran and exited with a non-zero status.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("guest command exited with status %d", e.Code) }

// Run runs argv in the guest. stdin, when non-nil, is streamed to the
// command and closed at EOF. Stdout goes to stdout; a write error stops the
// command and is returned. The guest's stderr is discarded: an untrusted
// guest must not reach host logs or errors.
func Run(ctx context.Context, dial Dialer, argv []string, stdin io.Reader, stdout io.Writer) error {
	conn, err := start(ctx, dial, argv, stdin != nil)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	sent := make(chan struct{})
	if stdin != nil {
		go func() {
			defer close(sent)
			sendStdin(conn, stdin)
		}()
	} else {
		close(sent)
	}
	// Closing first unblocks the stdin sender; waiting keeps the caller's
	// reader from being used after Run returns.
	defer func() { _ = conn.Close(); <-sent }()
	buf := make([]byte, maxFrame)
	for {
		kind, p, err := readFrame(conn, buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("%w: %v", ErrUnavailable, err) //nolint:errorlint // Transport detail only.
		}
		switch kind {
		case frameStdout:
			if _, err := stdout.Write(p); err != nil {
				return err
			}
		case frameStderr:
		case frameExit:
			return exitResult(p)
		case frameFailed:
			return ErrNotStarted
		default:
			return errFrame
		}
	}
}

func start(ctx context.Context, dial Dialer, argv []string, stdin bool) (net.Conn, error) {
	req, err := json.Marshal(request{Version: Version, Argv: argv, Stdin: stdin})
	if err != nil {
		return nil, err
	}
	if err := (request{Version: Version, Argv: argv}).validate(); err != nil {
		return nil, err
	}
	conn, err := dial(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err) //nolint:errorlint // Transport detail only.
	}
	if err := writeFrame(conn, frameRequest, req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err) //nolint:errorlint // Transport detail only.
	}
	return conn, nil
}

func sendStdin(conn net.Conn, stdin io.Reader) {
	buf := make([]byte, chunk)
	for {
		n, err := stdin.Read(buf)
		if n > 0 {
			if writeFrame(conn, frameStdin, buf[:n]) != nil {
				return
			}
		}
		if errors.Is(err, io.EOF) {
			_ = writeFrame(conn, frameStdin, nil)
			return
		}
		if err != nil {
			// Never let a truncated input look complete: abandon the command.
			_ = conn.Close()
			return
		}
	}
}

func exitResult(p []byte) error {
	if len(p) != 4 {
		return errFrame
	}
	code := int32(binary.BigEndian.Uint32(p)) //nolint:gosec // Two's complement on purpose.
	if code == 0 {
		return nil
	}
	return &ExitError{Code: int(code)}
}

// Duplex runs argv with a binary-safe stream in both directions: writes go
// to the command's stdin, reads come from its stdout, and the stream ends
// when the command exits. Closing the stream kills the command.
func Duplex(ctx context.Context, dial Dialer, argv []string) (net.Conn, error) {
	conn, err := start(ctx, dial, argv, true)
	if err != nil {
		return nil, err
	}
	return &duplex{conn: conn}, nil
}

type duplex struct {
	conn    net.Conn
	readMu  sync.Mutex
	pending []byte
	ended   error
	buf     []byte
	writeMu sync.Mutex
}

func (d *duplex) Read(p []byte) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	for len(d.pending) == 0 {
		if d.ended != nil {
			return 0, d.ended
		}
		if d.buf == nil {
			d.buf = make([]byte, maxFrame)
		}
		kind, payload, err := readFrame(d.conn, d.buf)
		switch {
		case err != nil:
			d.ended = err
		case kind == frameStdout:
			d.pending = payload
		case kind == frameStderr:
		case kind == frameExit || kind == frameFailed:
			d.ended = io.EOF
		default:
			d.ended = errFrame
		}
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

func (d *duplex) Write(p []byte) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		n := min(len(p), chunk)
		if err := writeFrame(d.conn, frameStdin, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite sends EOF to the command's stdin.
func (d *duplex) CloseWrite() error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return writeFrame(d.conn, frameStdin, nil)
}

func (d *duplex) Close() error                       { return d.conn.Close() }
func (d *duplex) LocalAddr() net.Addr                { return d.conn.LocalAddr() }
func (d *duplex) RemoteAddr() net.Addr               { return d.conn.RemoteAddr() }
func (d *duplex) SetDeadline(t time.Time) error      { return d.conn.SetDeadline(t) }
func (d *duplex) SetReadDeadline(t time.Time) error  { return d.conn.SetReadDeadline(t) }
func (d *duplex) SetWriteDeadline(t time.Time) error { return d.conn.SetWriteDeadline(t) }
