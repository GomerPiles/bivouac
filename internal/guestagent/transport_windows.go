//go:build windows

package guestagent

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/GomerPiles/bivouac/internal/hvsock"
	winio "github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
)

type hostListener struct{ net.Listener }

func (l hostListener) Accept() (io.ReadWriteCloser, error) { return l.Listener.Accept() }

func listenWindows(open func(*winio.HvsockAddr) (net.Listener, error)) (Listener, error) {
	service, err := guid.FromString(ServiceID)
	if err != nil {
		return nil, errors.New("invalid agent service")
	}
	l, err := open(&winio.HvsockAddr{VMID: winio.HvsockGUIDParent(), ServiceID: service})
	if err != nil {
		return nil, errors.New("agent listener unavailable")
	}
	return hostListener{l}, nil
}

// DialHvsock opens one connection to a VM runtime ID, retrying only connection
// establishment (never a command). Attempts last at most 3 s, separated by
// 500 ms, just like the current HCS App Sandbox agent transport. Callers own
// the overall context deadline. No input is sent by this dialer.
func DialHvsock(runtimeID string) Dialer {
	return DialHvsockObserved(runtimeID, nil)
}

// DialHvsockObserved is DialHvsock with a numeric-only retry observation. The
// callback runs synchronously after a failed connection attempt, never a command.
func DialHvsockObserved(runtimeID string, retry func()) Dialer {
	return dialHvsock(runtimeID, func(ctx context.Context, addr hvsock.Addr) (net.Conn, error) {
		conn, err := hvsock.Dial(ctx, addr)
		if err != nil && retry != nil {
			retry()
		}
		return conn, err
	}, 3*time.Second, 500*time.Millisecond)
}

func dialHvsock(runtimeID string, dial func(context.Context, hvsock.Addr) (net.Conn, error), attemptTimeout, pause time.Duration) Dialer {
	vm, vmErr := hvsock.ParseGUID(runtimeID)
	service, serviceErr := hvsock.ParseGUID(ServiceID)
	return func(ctx context.Context) (net.Conn, error) {
		if vmErr != nil || serviceErr != nil {
			return nil, errors.New("invalid guest runtime identity")
		}
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			attempt, cancel := context.WithTimeout(ctx, attemptTimeout)
			conn, err := dial(attempt, hvsock.Addr{VMID: vm, ServiceID: service})
			cancel()
			if conn != nil && err == nil {
				if err := ctx.Err(); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return conn, nil
			}
			if conn != nil {
				_ = conn.Close()
			}
			timer := time.NewTimer(pause)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
	}
}
