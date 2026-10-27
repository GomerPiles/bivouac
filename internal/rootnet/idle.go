package rootnet

import (
	"net"
	"sync"
	"time"
)

// Both TCP directions share one idle policy. The first propagated FIN reduces
// the remaining flow's inactivity timeout and updates an already blocked read.
type idleState struct {
	mu    sync.Mutex
	idle  time.Duration
	conns []net.Conn
}

func newIdleState(idle time.Duration) *idleState      { return &idleState{idle: idle} }
func (s *idleState) setConnections(conns ...net.Conn) { s.conns = conns }
func (s *idleState) touch(halfClosed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if halfClosed {
		s.idle = min(s.idle, 15*time.Minute)
	}
	for _, c := range s.conns {
		_ = c.SetDeadline(time.Now().Add(s.idle))
	}
}

type idleConn struct {
	net.Conn
	state *idleState
}

func (c *idleConn) Read(b []byte) (int, error)  { c.state.touch(false); return c.Conn.Read(b) }
func (c *idleConn) Write(b []byte) (int, error) { c.state.touch(false); return c.Conn.Write(b) }
func (c *idleConn) CloseWrite() error {
	c.state.touch(true)
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return c.Close()
}
