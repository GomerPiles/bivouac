package guestagent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

func diagnosticFixture(t *testing.T, failed bool) Dialer {
	t.Helper()
	return func(context.Context) (net.Conn, error) {
		host, guest := net.Pipe()
		done := make(chan struct{})
		t.Cleanup(func() { _ = host.Close(); <-done })
		go func() {
			defer close(done)
			defer func() { _ = guest.Close() }()
			if _, _, err := readFrame(guest, nil); err != nil {
				return
			}
			for _, frame := range []struct {
				kind byte
				data string
			}{{frameStderr, "Authorization: Bearer synthetic-"}, {frameStderr, "credential\n"}, {frameStdout, "metrics"}} {
				if writeFrame(guest, frame.kind, []byte(frame.data)) != nil {
					return
				}
			}
			if failed {
				_ = writeFrame(guest, frameFailed, []byte("opaque private failure"))
				return
			}
			var exit [4]byte
			binary.BigEndian.PutUint32(exit[:], 3)
			_ = writeFrame(guest, frameExit, exit[:])
		}()
		return host, nil
	}
}

func TestDiagnosticRunRedactsStderrAndPreservesExit(t *testing.T) {
	var output bytes.Buffer
	stderr := NewDiagnosticStderr()
	err := RunWithStderr(context.Background(), diagnosticFixture(t, false), []string{"fixture"}, nil, &output, stderr)
	_ = stderr.Close()
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 3 || output.String() != "metrics" {
		t.Fatal("diagnostic command lost stdout or exit status")
	}
	text, truncated := stderr.Text()
	if truncated || strings.Contains(text, "synthetic-credential") || !strings.Contains(text, "<redacted>") {
		t.Fatal("stderr was not redacted across frames")
	}
	var normal bytes.Buffer
	err = Run(context.Background(), diagnosticFixture(t, false), []string{"fixture"}, nil, &normal)
	if !errors.As(err, &exit) || normal.String() != "metrics" || strings.Contains(err.Error(), "credential") {
		t.Fatal("ordinary Run exposed stderr")
	}
}

func TestDiagnosticDuplexReportsTerminalErrors(t *testing.T) {
	for _, failed := range []bool{false, true} {
		stderr := NewDiagnosticStderr()
		stream, err := DuplexWithStderr(context.Background(), diagnosticFixture(t, failed), []string{"fixture"}, stderr)
		if err != nil {
			t.Fatal(err)
		}
		output, err := io.ReadAll(stream)
		_ = stream.Close()
		_ = stderr.Close()
		var exit *ExitError
		if string(output) != "metrics" || (failed && !errors.Is(err, ErrFailed)) || (!failed && (!errors.As(err, &exit) || exit.Code != 3)) {
			t.Fatal("diagnostic duplex swallowed terminal error")
		}
		text, _ := stderr.Text()
		if strings.Contains(text, "synthetic-credential") {
			t.Fatal("duplex stderr not redacted")
		}
	}
	// The ordinary opaque-stream contract keeps its existing EOF behavior.
	stream, err := Duplex(context.Background(), diagnosticFixture(t, false), []string{"fixture"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, stream)
	_ = stream.Close()
	if err != nil {
		t.Fatal("ordinary duplex exit behavior changed")
	}
}

func TestDiagnosticStderrBoundsAndFixedErrorClasses(t *testing.T) {
	stderr := NewDiagnosticStderr()
	_, _ = stderr.Write([]byte("/Users/synthetic/source.go\n"))
	_, _ = stderr.Write([]byte(strings.Repeat("bounded message\n", 2000)))
	_ = stderr.Close()
	text, truncated := stderr.Text()
	if !truncated || len(text) > 8<<10 || strings.Contains(text, "/Users/") {
		t.Fatal("diagnostics retained unbounded output or personal paths")
	}
	for _, test := range []struct {
		err   error
		class string
		code  int
	}{
		{nil, "none", 0}, {&ExitError{Code: 3}, "guest_exit", 3}, {ErrFailed, "agent_failed", -1}, {ErrUnavailable, "agent_unavailable", -1},
		{context.DeadlineExceeded, "deadline", -1}, {context.Canceled, "canceled", -1}, {&VersionError{}, "agent_version", -1},
		{errors.New("opaque private text"), "other", -1},
	} {
		class, code := DiagnosticError(test.err)
		if class != test.class || code != test.code {
			t.Fatal("unexpected diagnostic category")
		}
	}
}
