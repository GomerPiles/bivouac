//go:build windows

package guestagent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	refusalCount         = 5
	refusalMinimum       = 10 * time.Second
	refusalWindow        = 30 * time.Second
	listenerRetryMinimum = 100 * time.Millisecond
	listenerRetryMaximum = 5 * time.Second
)

// The accept loop owns refusal/backoff state. Close may run concurrently and
// pins closure under mu so a cancellation cannot leave a newly opened listener.
type sessionListener struct {
	ctx            context.Context
	open           func() (Listener, error)
	check          func() bool
	logger         *slog.Logger
	cancel         context.CancelFunc
	now            func() time.Time
	pause          func(time.Duration) error
	mu             sync.Mutex
	current        Listener
	closed         bool
	refused        bool
	consecutive    int
	refusalStarted time.Time
}

func newSessionListener(ctx context.Context, check func() bool, logger *slog.Logger, open func() (Listener, error)) *sessionListener {
	return &sessionListener{ctx: ctx, check: check, logger: logger, open: open, now: time.Now, pause: func(d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}}
}

func (l *sessionListener) Close() error {
	l.mu.Lock()
	l.closed = true
	current := l.current
	l.current = nil
	l.mu.Unlock()
	if current != nil {
		return current.Close()
	}
	return nil
}

func (l *sessionListener) listener() (Listener, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if l.current == nil {
		current, err := l.open()
		if err != nil {
			return nil, err
		}
		l.current = current
	}
	return l.current, nil
}

func (l *sessionListener) retire(current Listener) {
	l.mu.Lock()
	if l.current == current {
		l.current = nil
	}
	l.mu.Unlock()
	_ = current.Close()
}

func (l *sessionListener) refusal(now time.Time) bool {
	if l.refusalStarted.IsZero() || now.Sub(l.refusalStarted) > refusalWindow {
		l.refusalStarted = now
		l.consecutive = 0
	}
	l.consecutive = min(l.consecutive+1, refusalCount)
	return l.consecutive >= refusalCount && now.Sub(l.refusalStarted) >= refusalMinimum
}

func (l *sessionListener) Accept() (io.ReadWriteCloser, error) {
	backoff := listenerRetryMinimum
	for {
		current, err := l.listener()
		var conn io.ReadWriteCloser
		if err == nil {
			conn, err = current.Accept()
		}
		if err != nil {
			if current != nil {
				l.retire(current)
			}
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed || l.ctx.Err() != nil {
				return nil, net.ErrClosed
			}
			l.logger.Info("listener_retry")
			if l.pause(backoff) != nil {
				return nil, net.ErrClosed
			}
			backoff = min(backoff*2, listenerRetryMaximum)
			continue
		}
		backoff = listenerRetryMinimum
		if !l.check() {
			l.logger.Info("session_refused")
			// A bad session receives no command execution; the fixed response is
			// bounded even when a peer does not read it.
			timer := time.AfterFunc(time.Second, func() { _ = conn.Close() })
			_ = writeFrame(conn, frameFailed, []byte("session refused"))
			timer.Stop()
			_ = conn.Close()
			if l.refusal(l.now()) {
				l.refused = true
				if l.cancel != nil {
					l.cancel()
				}
				return nil, errors.New("agent session refused")
			}
			continue
		}
		l.consecutive = 0
		l.refusalStarted = time.Time{}
		l.logger.Info("connection_accepted")
		return conn, nil
	}
}
