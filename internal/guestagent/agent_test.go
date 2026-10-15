//go:build darwin || linux

package guestagent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type unixListener struct{ l net.Listener }

func (u unixListener) Accept() (io.ReadWriteCloser, error) { return u.l.Accept() }
func (u unixListener) Close() error                        { return u.l.Close() }

// agent serves on a Unix socket, standing in for the helper's proxy.
func agent(t *testing.T) Dialer {
	t.Helper()
	// Test names make t.TempDir too long for sun_path.
	dir, err := os.MkdirTemp("", "ga")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "a.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, unixListener{l}) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return DialUnix(path)
}

func TestRunStreamsStdoutAndExitStatus(t *testing.T) {
	dial := agent(t)
	var out bytes.Buffer
	err := Run(context.Background(), dial, []string{"/bin/sh", "-c", "printf hello; echo secret >&2; exit 3"}, nil, &out)
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 3 {
		t.Fatalf("err = %v", err)
	}
	if out.String() != "hello" || strings.Contains(err.Error(), "secret") {
		t.Fatalf("stdout %q, err %v", out.String(), err)
	}
	if err := Run(context.Background(), dial, []string{"/bin/sh", "-c", "kill -TERM $$"}, nil, io.Discard); !errors.As(err, &exit) || exit.Code != 143 {
		t.Fatalf("signalled exit = %v", err)
	}
}

func TestRunStreamsLargeStdin(t *testing.T) {
	dial := agent(t)
	in := bytes.Repeat([]byte("bivouac\x00\xff"), 50_000)
	var out bytes.Buffer
	if err := Run(context.Background(), dial, []string{"cat"}, bytes.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), in) {
		t.Fatalf("round trip of %d bytes returned %d", len(in), out.Len())
	}
}

func TestRunReportsCommandsThatCannotStart(t *testing.T) {
	dial := agent(t)
	if err := Run(context.Background(), dial, []string{"/nonexistent/command"}, nil, io.Discard); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("err = %v", err)
	}
	if err := Run(context.Background(), dial, nil, nil, io.Discard); err == nil {
		t.Fatal("ran an empty command")
	}
}

type failAfter struct{ n int }

var errFull = errors.New("full")

func (f *failAfter) Write(p []byte) (int, error) {
	if f.n -= len(p); f.n < 0 {
		return 0, errFull
	}
	return len(p), nil
}

func TestStdoutWriteErrorStopsCommand(t *testing.T) {
	dial := agent(t)
	start := time.Now()
	if err := Run(context.Background(), dial, []string{"yes"}, nil, &failAfter{n: 1 << 20}); !errors.Is(err, errFull) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("bounded output did not stop the command")
	}
}

func TestCancellationKillsCommand(t *testing.T) {
	dial := agent(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := Run(ctx, dial, []string{"sleep", "30"}, nil, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("cancellation did not return promptly")
	}
	// The agent's own cleanup (killing sleep) is joined by Serve at test end.
}

func TestUnreachableAgentIsUnavailable(t *testing.T) {
	dial := DialUnix(filepath.Join(t.TempDir(), "missing.sock"))
	if err := Run(context.Background(), dial, []string{"true"}, nil, io.Discard); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestDuplexIsBinarySafeAndHalfCloses(t *testing.T) {
	dial := agent(t)
	conn, err := Duplex(context.Background(), dial, []string{"cat"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	msg := bytes.Repeat([]byte{0, 1, 2, 255}, 40_000)
	go func() {
		_, _ = conn.Write(msg)
		_ = conn.(interface{ CloseWrite() error }).CloseWrite()
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("duplex returned %d of %d bytes", len(got), len(msg))
	}
}

func TestAgentRefusesOtherVersions(t *testing.T) {
	dial := agent(t)
	conn, err := dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := writeFrame(conn, frameRequest, []byte(`{"v":2,"argv":["true"]}`)); err != nil {
		t.Fatal(err)
	}
	kind, _, err := readFrame(conn, nil)
	if err != nil || kind != frameFailed {
		t.Fatalf("kind %q, err %v", kind, err)
	}
}

func TestFramesAreBounded(t *testing.T) {
	if err := writeFrame(io.Discard, frameStdout, make([]byte, maxFrame+1)); err == nil {
		t.Fatal("wrote an oversized frame")
	}
	header := []byte{frameStdout, 0, 2, 0, 0} // 128 KiB
	if _, _, err := readFrame(bytes.NewReader(header), nil); !errors.Is(err, errFrame) {
		t.Fatalf("err = %v", err)
	}
}
