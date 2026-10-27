package cache

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GomerPiles/bivouac/internal/engine"
)

// pipeListener exposes only an in-process cache handler, never a host socket.
type pipeListener struct {
	incoming chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.incoming:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (*pipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (l *pipeListener) dial(ctx context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.incoming <- server:
		return client, nil
	case <-l.done:
	case <-ctx.Done():
	}
	_ = server.Close()
	_ = client.Close()
	return nil, net.ErrClosed
}

type agentTransport struct {
	stream     net.Conn
	listener   *pipeListener
	server     *http.Server
	active     atomic.Int64
	closing    atomic.Bool
	lostOnce   sync.Once
	lostActive int64
}

func (t *agentTransport) Close() error {
	t.closing.Store(true)
	return errors.Join(t.stream.Close(), t.listener.Close(), t.server.Close())
}

type agentLossConn struct {
	net.Conn
	transport *agentTransport
}

func (c agentLossConn) lost(err error) {
	if err != nil {
		c.transport.lostOnce.Do(func() { c.transport.lostActive = c.transport.active.Load() })
	}
}
func (c agentLossConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.lost(err)
	return n, err
}
func (c agentLossConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.lost(err)
	return n, err
}

// AttachAgent owns one cache-listen command after reading its bounded port
// prelude. Attachment cancellation ends setup only; success lives until relay
// loss, revocation or service shutdown. There is no automatic reattachment.
func (s *Service) AttachAgent(ctx context.Context, name string, open func(context.Context) (net.Conn, error)) ([]byte, error) {
	u, err := url.Parse(s.url)
	if err != nil || u.Hostname() != "127.0.0.1" {
		return nil, errors.New("cache agent attachment requires loopback TLS identity")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stream, err := open(ctx)
	if err != nil {
		return nil, errors.New("guest cache agent unavailable")
	}
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	// Read exactly through the newline, leaving every engine byte untouched.
	var prelude []byte
	var one [1]byte
	for len(prelude) < 64 {
		if _, err := io.ReadFull(stream, one[:]); err != nil {
			_ = stream.Close()
			return nil, errors.New("guest cache port unavailable")
		}
		prelude = append(prelude, one[0])
		if one[0] == '\n' {
			break
		}
	}
	var port struct {
		Port int `json:"port"`
	}
	if len(prelude) == 0 || prelude[len(prelude)-1] != '\n' || json.Unmarshal(prelude, &port) != nil || port.Port < 1 || port.Port > 65535 {
		_ = stream.Close()
		return nil, errors.New("invalid guest cache port")
	}
	// Like the SSH transport it replaces, the relay keeps release-proxy
	// authority, still bounded by cache.release_proxy.
	bootstrap, err := s.issueAt(name, "https://127.0.0.1:"+strconv.Itoa(port.Port), GrantCapabilities{ReleaseProxy: true})
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	listener := &pipeListener{incoming: make(chan net.Conn), done: make(chan struct{})}
	server := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: serveTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	transport := &agentTransport{stream: stream, listener: listener, server: server}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		transport.active.Add(1)
		defer transport.active.Add(-1)
		s.ServeHTTP(w, r)
	})
	var issued Bootstrap
	if json.Unmarshal(bootstrap, &issued) != nil {
		clear(bootstrap)
		_ = transport.Close()
		return nil, errors.New("cache bootstrap unavailable")
	}
	s.mu.Lock()
	grant, valid := s.grants[issued.Token]
	if s.closed || !valid || grant.name != name || ctx.Err() != nil {
		s.mu.Unlock()
		clear(bootstrap)
		_ = transport.Close()
		s.Revoke(name)
		return nil, errors.New("cache closed during agent attachment")
	}
	s.transports[name] = transport
	s.mu.Unlock()
	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{s.certificate}, MinVersion: tls.VersionTLS12}))
	}()
	go func() {
		_ = engine.Relay(s.work, agentLossConn{Conn: stream, transport: transport}, listener.dial, 64)
		transport.lostOnce.Do(func() { transport.lostActive = transport.active.Load() })
		if transport.lostActive > 0 && !transport.closing.Load() {
			s.log.Warn("cache agent transport ended during requests", "guest", name, "reason", "agent_closed", "active_requests", transport.lostActive)
		}
		_ = transport.Close()
	}()
	return bootstrap, nil
}
