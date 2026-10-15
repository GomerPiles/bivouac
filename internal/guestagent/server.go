//go:build darwin || linux

package guestagent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	// requestTimeout bounds how long a connection may wait to name a command.
	requestTimeout = 30 * time.Second
	// outputDelay bounds how long output is still forwarded after the
	// command exits, when a background child it started keeps a pipe open.
	outputDelay = 10 * time.Second
)

// RunAgent is `bivouac guest-agent`: it serves the host on Port until ctx ends.
func RunAgent(ctx context.Context) error {
	l, err := listen(Port)
	if err != nil {
		return err
	}
	return Serve(ctx, l)
}

// Listener yields host connections. Implementations drop connections from
// any peer other than the host.
type Listener interface {
	Accept() (io.ReadWriteCloser, error)
	Close() error
}

// Serve runs one command per accepted connection until ctx ends or the
// listener fails.
func Serve(ctx context.Context, l Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() { handle(ctx, conn) })
	}
}

func handle(ctx context.Context, conn io.ReadWriteCloser) {
	defer func() { _ = conn.Close() }()
	timer := time.AfterFunc(requestTimeout, func() { _ = conn.Close() })
	kind, payload, err := readFrame(conn, nil)
	if !timer.Stop() || err != nil || kind != frameRequest {
		return
	}
	w := &lockedWriter{w: conn}
	var req request
	if err := json.Unmarshal(payload, &req); err != nil {
		_ = w.frame(frameFailed, []byte("invalid request"))
		return
	}
	if err := req.validate(); err != nil {
		var version *VersionError
		if errors.As(err, &version) {
			_ = w.frame(frameFailed, versionFailure())
		} else {
			_ = w.frame(frameFailed, []byte("invalid request"))
		}
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, req.Argv[0], req.Argv[1:]...)
	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}
	cmd.Stdout = frameWriter{w: w, kind: frameStdout}
	cmd.Stderr = frameWriter{w: w, kind: frameStderr}
	cmd.WaitDelay = outputDelay
	var stdin io.WriteCloser
	if req.Stdin {
		if stdin, err = cmd.StdinPipe(); err != nil {
			_ = w.frame(frameFailed, []byte("stdin unavailable"))
			return
		}
	}
	if err := cmd.Start(); err != nil {
		_ = w.frame(frameFailed, []byte("command did not start"))
		return
	}
	go readStdin(conn, stdin, cancel)
	err = cmd.Wait()
	if cmd.ProcessState == nil {
		_ = w.frame(frameFailed, []byte("command lost"))
		return
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		// A background child kept a pipe open past outputDelay: output may be
		// incomplete, so success must not be reported.
		_ = w.frame(frameFailed, []byte("output incomplete"))
		return
	}
	var code [4]byte
	binary.BigEndian.PutUint32(code[:], uint32(exitCode(cmd.ProcessState))) //nolint:gosec // Two's complement on purpose.
	_ = w.frame(frameExit, code[:])
}

// versionFailure is the agent's answer to a request of another version.
func versionFailure() []byte { return []byte(versionPrefix + strconv.Itoa(Version)) }

// readStdin forwards host stdin frames. A closed connection, or any frame
// out of protocol, means the host is gone: the command is killed.
func readStdin(conn io.Reader, stdin io.WriteCloser, cancel func()) {
	buf := make([]byte, maxFrame)
	for {
		kind, p, err := readFrame(conn, buf)
		if err != nil || kind != frameStdin {
			cancel()
			return
		}
		if stdin == nil {
			continue
		}
		if len(p) == 0 {
			_ = stdin.Close()
			stdin = nil
			continue
		}
		if _, err := stdin.Write(p); err != nil {
			// The command stopped reading; the rest is discarded.
			_ = stdin.Close()
			stdin = nil
		}
	}
}

func exitCode(state *os.ProcessState) int32 {
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int32(ws.Signal()) //nolint:gosec // Signal numbers are small.
	}
	return int32(state.ExitCode()) //nolint:gosec // Exit codes fit in a byte.
}

type lockedWriter struct {
	mu  sync.Mutex
	w   io.Writer
	err error
}

func (l *lockedWriter) frame(kind byte, p []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err == nil {
		l.err = writeFrame(l.w, kind, p)
	}
	if l.err != nil {
		return errors.Join(errors.New("host connection lost"), l.err)
	}
	return nil
}

// frameWriter sends everything written to it as frames of one kind.
type frameWriter struct {
	w    *lockedWriter
	kind byte
}

func (f frameWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), chunk)
		if err := f.w.frame(f.kind, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}
