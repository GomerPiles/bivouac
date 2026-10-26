package cache

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
)

// admissionTransport preserves pooling, but rechecks the actual peer before a
// reused connection receives a new request. Checking DNS alone would miss a
// pooled peer whose route became local after it was dialed.
type admissionTransport struct {
	transport *http.Transport
	admit     func(net.IP) bool
}

func (t *admissionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		host, _, err := net.SplitHostPort(info.Conn.RemoteAddr().String())
		if err != nil || !t.admit(net.ParseIP(host)) {
			_ = info.Conn.Close()
		}
	}}
	return t.transport.RoundTrip(r.WithContext(httptrace.WithClientTrace(r.Context(), trace)))
}
func (t *admissionTransport) CloseIdleConnections() { t.transport.CloseIdleConnections() }
func upstreamTransport(c *http.Client) *http.Transport {
	if t, ok := c.Transport.(*admissionTransport); ok {
		return t.transport
	}
	return c.Transport.(*http.Transport)
}

// checkedUpstream also revalidates long-lived opaque tunnels and response
// streams. Every I/O consults the service's shared admission snapshot, so
// connection-level throttling cannot add another observation interval.
type checkedUpstream struct {
	net.Conn
	admit func(net.IP) bool
	ip    net.IP
	mu    sync.Mutex
}

func (c *checkedUpstream) allowed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.admit(c.ip) {
		_ = c.Close()
		return false
	}
	return true
}
func (c *checkedUpstream) Read(p []byte) (int, error) {
	if !c.allowed() {
		return 0, errors.New("upstream policy refused")
	}
	n, err := c.Conn.Read(p)
	if !c.allowed() {
		clear(p[:n])
		return 0, errors.New("upstream policy refused")
	}
	return n, err
}
func (c *checkedUpstream) Write(p []byte) (int, error) {
	if !c.allowed() {
		return 0, errors.New("upstream policy refused")
	}
	return c.Conn.Write(p)
}
