package tart

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/GomerPiles/bivouac/internal/redact"
)

// Exec runs the tart binary. Tests substitute a recorder.
type Exec interface {
	// Run runs args to completion with optional stdin, streaming stdout to w.
	// A write error from w stops the command and fails the call. Stderr is
	// bounded by the implementation.
	Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error
	// Start launches a long-running command whose output goes to sink.
	Start(ctx context.Context, args []string, sink io.Writer) (Process, error)
}

// Output bounds. Guest commands can print anything, so every call has a cap
// and exceeding it fails the call instead of truncating.
const (
	defaultOutputLimit = 64 << 10
	statusOutputLimit  = 4 << 10
	listOutputLimit    = 4 << 20 // host-side VM inventory
	stderrLimit        = 8 << 10
)

// execWaitDelay bounds how long Wait waits for output copying after a child
// exits or its context ends.
const execWaitDelay = 5 * time.Second

// ErrOutputLimit reports a command whose stdout or stderr exceeded its bound.
var ErrOutputLimit = errors.New("output exceeded its bound")

// output runs args and returns at most limit bytes of stdout.
func output(ctx context.Context, e Exec, args []string, stdin io.Reader, limit int) ([]byte, error) {
	b := &boundedBuffer{limit: limit}
	err := e.Run(ctx, args, stdin, b)
	if b.exceeded {
		return nil, &Error{Args: args, Err: fmt.Errorf("stdout %w of %d bytes", ErrOutputLimit, limit)}
	}
	if err != nil {
		return nil, err
	}
	return b.data, nil
}

// boundedBuffer fails the write that would exceed limit.
type boundedBuffer struct {
	data     []byte
	limit    int
	exceeded bool
	onExceed func()
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > b.limit {
		b.exceeded = true
		if b.onExceed != nil {
			b.onExceed()
		}
		return 0, ErrOutputLimit
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

// failWriter remembers the first error from w and stops the command.
type failWriter struct {
	w      io.Writer
	err    error
	cancel func()
}

func (f *failWriter) Write(p []byte) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	n, err := f.w.Write(p)
	if err != nil {
		f.err = err
		f.cancel()
	}
	return n, err
}

// Duplex attaches a binary-safe, non-PTY guest exec stream. Stderr is discarded:
// an untrusted guest must not send container credentials into host diagnostics.
func (c CLI) Duplex(ctx context.Context, args []string) (net.Conn, error) {
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	cmd.Env = append(os.Environ(), c.Env...)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		_ = in.Close()
		return nil, err
	}
	cmd.Stderr = io.Discard
	// Killing this `tart exec` stream never affects the VM. WaitDelay bounds
	// Close and cancellation when a grandchild still holds a pipe open.
	cmd.WaitDelay = execWaitDelay
	if err = cmd.Start(); err != nil {
		_ = in.Close()
		_ = out.Close()
		return nil, errors.New("start guest transport")
	}
	s := &execConn{cmd: cmd, in: in, out: out, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(s.done) }()
	return s, nil
}

type execConn struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  io.ReadCloser
	done chan struct{}
}

func (s *execConn) Read(p []byte) (int, error)  { return s.out.Read(p) }
func (s *execConn) Write(p []byte) (int, error) { return s.in.Write(p) }
func (s *execConn) CloseWrite() error           { return s.in.Close() }
func (s *execConn) Close() error {
	_ = s.in.Close()
	_ = s.out.Close()
	_ = s.cmd.Process.Kill()
	<-s.done
	return nil
}
func (*execConn) LocalAddr() net.Addr  { return execAddr("host-vsock") }
func (*execConn) RemoteAddr() net.Addr { return execAddr("guest-vsock") }
func (*execConn) SetDeadline(time.Time) error {
	return errors.New("exec stream uses context deadlines")
}
func (*execConn) SetReadDeadline(time.Time) error {
	return errors.New("exec stream uses context deadlines")
}
func (*execConn) SetWriteDeadline(time.Time) error {
	return errors.New("exec stream uses context deadlines")
}

type execAddr string

func (a execAddr) Network() string { return "vsock" }
func (a execAddr) String() string  { return string(a) }

// Process is a started command.
type Process interface {
	PID() int
	// Done is closed when the process exits.
	Done() <-chan struct{}
	// Err is the exit error, valid after Done.
	Err() error
	Kill() error
}

// CLI runs the real binary.
type CLI struct {
	Binary string
	// Env entries are appended to the environment (TART_HOME, TART_NO_AUTO_PRUNE).
	Env []string
}

// Run implements Exec. Stderr beyond stderrLimit fails the call; a failing
// stdout writer stops the command.
func (c CLI) Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, c.Binary, args...)
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdin = stdin
	// A short-lived call: after cancellation or exit, a grandchild holding
	// stdout or stderr open cannot delay the return past teardown deadlines.
	cmd.WaitDelay = execWaitDelay
	out := &failWriter{w: stdout, cancel: cancel}
	stderr := &boundedBuffer{limit: stderrLimit, onExceed: cancel}
	cmd.Stdout, cmd.Stderr = out, stderr
	err := cmd.Run()
	defer clear(stderr.data)
	switch {
	case out.err != nil:
		return &Error{Args: args, Err: out.err}
	case ctx.Err() != nil:
		return &Error{Args: args, Err: ctx.Err()}
	case stderr.exceeded:
		return &Error{Args: args, Err: fmt.Errorf("stderr %w of %d bytes", ErrOutputLimit, stderrLimit)}
	case err != nil:
		return &Error{Args: args, Err: err, Stderr: strings.TrimSpace(string(stderr.data))}
	}
	return nil
}

// Start implements Exec.
func (c CLI) Start(ctx context.Context, args []string, sink io.Writer) (Process, error) {
	return c.startInput(ctx, args, nil, sink)
}

// startInput launches a child that must survive the daemon (`tart run`, the
// container relay): it gets its own process group so a terminal interrupt
// aimed at a foreground daemon does not reach it.
//
// It is deliberately not bound to ctx, which is checked only before starting:
// with a context, cancellation plus WaitDelay would signal and then kill a
// running guest when the daemon stops. Without one, the WaitDelay timer starts
// only once the child has exited, and then merely stops Done from waiting on a
// grandchild that inherited a copied stdin/stdout pipe.
func (c CLI) startInput(ctx context.Context, args []string, stdin io.Reader, sink io.Writer) (Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, &Error{Args: args, Err: err}
	}
	cmd := exec.Command(c.Binary, args...)
	cmd.Stdin = stdin
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdout, cmd.Stderr = sink, sink
	cmd.WaitDelay = execWaitDelay
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return nil, &Error{Args: args, Err: err}
	}
	p := &process{cmd: cmd, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

type process struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func (p *process) PID() int              { return p.cmd.Process.Pid }
func (p *process) Done() <-chan struct{} { return p.done }
func (p *process) Err() error {
	<-p.done
	return p.err
}
func (p *process) Kill() error {
	err := p.cmd.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

// Error is a failed tart invocation. Stderr holds at most stderrLimit bytes
// for classification; Error() never includes guest-controlled text.
type Error struct {
	Args   []string
	Err    error
	Stderr string
}

// Error reports the arguments and failure. Stderr from Tart's own commands is
// included redacted, on one line, and clipped; stderr of `tart exec` comes
// from the guest and is omitted.
func (e *Error) Error() string {
	msg := fmt.Sprintf("tart %s: %v", clip(strings.Join(e.Args, " "), 256), e.Err)
	if e.Stderr != "" && (len(e.Args) == 0 || e.Args[0] != "exec") {
		msg += ": " + clip(oneLine(redact.String(e.Stderr)), 512)
	}
	return msg
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...(truncated)"
}

func (e *Error) Unwrap() error { return e.Err }

// absent reports whether an error says the VM does not exist.
func absent(err error) bool {
	var te *Error
	if !errors.As(err, &te) {
		return false
	}
	s := strings.ToLower(te.Stderr)
	return strings.Contains(s, "not found") || strings.Contains(s, "does not exist") || strings.Contains(s, "doesn't exist")
}
