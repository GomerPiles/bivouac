//go:build windows

package guestagent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSessionRefusalDoesNotEndListener(t *testing.T) {
	base := &pipeListener{make(chan io.ReadWriteCloser, 2), make(chan struct{})}
	checks := 0
	l := newSessionListener(t.Context(), func() bool { checks++; return checks > 1 }, slog.New(slog.NewTextHandler(io.Discard, nil)), func() (Listener, error) { return base, nil })
	defer func() { _ = l.Close() }()
	host, bad := net.Pipe()
	defer func() { _ = host.Close() }()
	good, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	base.connections <- bad
	base.connections <- good
	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	kind, p, err := readFrame(host, nil)
	if err != nil || kind != frameFailed || string(p) != "session refused" {
		t.Fatal("missing fixed refusal", err)
	}
	if err := <-done; err != nil || checks != 2 || l.refused {
		t.Fatal("one session refusal killed listener", err)
	}
}

type failedListener struct{}

func (failedListener) Accept() (io.ReadWriteCloser, error) {
	return nil, errors.New("private native error")
}
func (failedListener) Close() error { return nil }

func TestListenerRelistensWithCappedBackoff(t *testing.T) {
	base := &pipeListener{make(chan io.ReadWriteCloser, 1), make(chan struct{})}
	host, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	base.connections <- host
	opens := 0
	var delays []time.Duration
	l := newSessionListener(t.Context(), func() bool { return true }, slog.New(slog.NewTextHandler(io.Discard, nil)), func() (Listener, error) {
		opens++
		if opens < 10 {
			return failedListener{}, nil
		}
		return base, nil
	})
	l.pause = func(delay time.Duration) error { delays = append(delays, delay); return nil }
	defer func() { _ = l.Close() }()
	conn, err := l.Accept()
	if err != nil || conn == nil {
		t.Fatal("listener did not recover", err)
	}
	_ = conn.Close()
	if len(delays) != 9 || delays[0] != 100*time.Millisecond || delays[6] != 5*time.Second || delays[8] != 5*time.Second {
		t.Fatal("unbounded or incorrect retry backoff", delays)
	}
}

func TestSessionConsecutiveRefusalWindow(t *testing.T) {
	start := time.Unix(100, 0)
	l := &sessionListener{}
	for i, elapsed := range []time.Duration{0, 2 * time.Second, 4 * time.Second, 6 * time.Second, 10 * time.Second} {
		if l.refusal(start.Add(elapsed)) != (i == 4) {
			t.Fatal("incorrect refusal threshold")
		}
	}
	if l.refusal(start.Add(31 * time.Second)) {
		t.Fatal("refusal window did not reset")
	}
}

func TestListenerBackoffCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	l := newSessionListener(ctx, func() bool { return true }, slog.New(slog.NewTextHandler(io.Discard, nil)), func() (Listener, error) { return nil, errors.New("private native error") })
	l.pause = func(time.Duration) error { cancel(); return ctx.Err() }
	if _, err := l.Accept(); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("retry cancellation or error disclosure")
	}
}
