package rootnet

import (
	"net"
	"sync"
	"testing"
	"time"
)

type deadlineConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
}

func (c *deadlineConn) SetDeadline(d time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = d
	return nil
}
func (*deadlineConn) CloseWrite() error { return nil }
func TestHalfCloseShortensBothIdleDeadlines(t *testing.T) {
	for _, idle := range []time.Duration{24 * time.Hour, 30 * time.Second} {
		state := newIdleState(idle)
		a, b := &deadlineConn{}, &deadlineConn{}
		ca, cb := &idleConn{Conn: a, state: state}, &idleConn{Conn: b, state: state}
		state.setConnections(ca, cb)
		state.touch(false)
		if time.Until(a.deadline) < idle-time.Second {
			t.Fatal("initial timeout changed")
		}
		if err := ca.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		state.touch(false)
		for _, c := range []*deadlineConn{a, b} {
			remaining := time.Until(c.deadline)
			want := min(idle, 15*time.Minute)
			if remaining > want || remaining < want-time.Second {
				t.Fatal("half-close idle policy not applied to both peers")
			}
		}
	}
}
