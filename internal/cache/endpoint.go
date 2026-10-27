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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/cachelink"
	"github.com/GomerPiles/bivouac/internal/streamrelay"
)

// endpointTransport keeps VSOCK only as a lifetime/port announcement. Cache
// payloads traverse the synthetic endpoint and a cache-only Unix capability.
type endpointTransport struct {
	control               net.Conn
	listener              net.Listener
	revocationListener    net.Listener
	server                *http.Server
	revocationServer      *http.Server
	mu                    sync.Mutex
	connections           map[net.Conn]struct{}
	revocationConnections map[net.Conn]struct{}
	maxConnections        int
	closed                bool
	once                  sync.Once
}

func (t *endpointTransport) Close() error {
	t.once.Do(func() {
		_ = t.control.Close()
		_ = t.listener.Close()
		_ = t.revocationListener.Close()
		_ = t.server.Close()
		_ = t.revocationServer.Close()
		t.mu.Lock()
		t.closed = true
		conns := make([]net.Conn, 0, len(t.connections))
		for c := range t.connections {
			conns = append(conns, c)
		}
		for c := range t.revocationConnections {
			conns = append(conns, c)
		}
		t.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return nil
}

// Track the underlying sockets, including hijacked CONNECT tunnels. Closing a
// tunnel releases its entry; a long job cannot grow a history of closed FDs.
type endpointListener struct {
	net.Listener
	owner      *endpointTransport
	revocation bool
}

func (l *endpointListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		wrapped := &endpointConn{Conn: c, owner: l.owner, revocation: l.revocation}
		l.owner.mu.Lock()
		connections := l.owner.connections
		limit := l.owner.maxConnections
		if limit == 0 {
			limit = 256
		}
		if l.revocation {
			connections = l.owner.revocationConnections
			limit = cachelink.MaxRevocationConnections
		}
		admitted := !l.owner.closed && len(connections) < limit
		if admitted {
			connections[wrapped] = struct{}{}
		}
		l.owner.mu.Unlock()
		if admitted {
			return wrapped, nil
		}
		_ = c.Close()
	}
}

type endpointConn struct {
	net.Conn
	owner      *endpointTransport
	revocation bool
	once       sync.Once
}

func (c *endpointConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.owner.mu.Lock()
		if c.revocation {
			delete(c.owner.revocationConnections, c)
		} else {
			delete(c.owner.connections, c)
		}
		c.owner.mu.Unlock()
	})
	return err
}

// AttachEndpoint requires current provider ownership and isolation proof. listener
// must be the provider-owned per-VM cache capability, never guest-selected.
// A successful attachment survives the setup context and is revoked by name.
func (s *Service) AttachEndpoint(ctx context.Context, name string, control net.Conn, l, revocation net.Listener) ([]byte, error) {
	if control == nil || l == nil || revocation == nil {
		if revocation != nil {
			_ = revocation.Close()
		}
		if control != nil {
			_ = control.Close()
		}
		if l != nil {
			_ = l.Close()
		}
		return nil, errors.New("cache endpoint capability unavailable")
	}
	fail := func() ([]byte, error) {
		_ = control.Close()
		_ = l.Close()
		_ = revocation.Close()
		return nil, errors.New("guest cache endpoint setup failed")
	}
	stop := context.AfterFunc(ctx, func() { _ = control.Close() })
	defer stop()
	port, err := readCachePort(control)
	if err != nil {
		return fail()
	}
	bootstrap, err := s.issueAt(name, "https://127.0.0.1:"+port)
	if err != nil {
		_ = l.Close()
		return fail()
	}
	t := &endpointTransport{maxConnections: s.MaxEndpointConnections(), control: control, listener: l, revocationListener: revocation, connections: map[net.Conn]struct{}{}, revocationConnections: map[net.Conn]struct{}{}}
	t.revocationServer = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.proxy.enabled.Load() || r.URL.IsAbs() || r.URL.Path != "/ca.crl" || r.URL.RawQuery != "" || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			http.NotFound(w, r)
			return
		}
		s.serveRevocationList(w, r)
	}), ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	t.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.endpointOwner(name, r) {
			switch {
			case r.Method == http.MethodConnect || r.URL.IsAbs():
				http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			case strings.HasPrefix(r.URL.Path, "/upload/"):
				relayUnavailable(w)
			default:
				http.Error(w, "invalid cache capability", http.StatusUnauthorized)
			}
			return
		}
		s.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: serveTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	var issued Bootstrap
	if json.Unmarshal(bootstrap, &issued) != nil {
		_ = t.Close()
		clear(bootstrap)
		return nil, errors.New("cache bootstrap unavailable")
	}
	issued.RevocationURL = cachelink.RevocationURL
	clear(bootstrap)
	bootstrap, err = json.Marshal(issued)
	if err != nil {
		_ = t.Close()
		s.Revoke(name)
		return nil, errors.New("cache bootstrap unavailable")
	}
	s.mu.Lock()
	g, valid := s.grants[issued.Token]
	if s.closed || !valid || g.name != name || ctx.Err() != nil {
		s.mu.Unlock()
		_ = t.Close()
		clear(bootstrap)
		s.Revoke(name)
		return nil, errors.New("cache closed during endpoint setup")
	}
	g.crlURL = cachelink.RevocationURL
	s.grants[issued.Token] = g
	s.transports[name] = t
	s.mu.Unlock()
	go func() {
		_ = t.server.Serve(tls.NewListener(&endpointListener{Listener: l, owner: t}, &tls.Config{Certificates: []tls.Certificate{s.certificate}, MinVersion: tls.VersionTLS12}))
		_ = t.Close()
	}()
	go func() {
		_ = t.revocationServer.Serve(&endpointListener{Listener: revocation, owner: t, revocation: true})
		_ = t.Close()
	}()
	go func() { var b [1]byte; _, _ = control.Read(b[:]); _ = t.Close() }()
	return bootstrap, nil
}
func readCachePort(control net.Conn) (string, error) {
	if control.SetReadDeadline(time.Now().Add(10*time.Second)) != nil {
		return "", errors.New("cache control unavailable")
	}
	defer func() { _ = control.SetReadDeadline(time.Time{}) }()
	var h [6]byte
	for n := 0; n < len(h); n++ {
		if _, err := io.ReadFull(control, h[n:n+1]); err != nil {
			return "", errors.New("cache control unavailable")
		}
		if h[n] != '\n' {
			continue
		}
		port, err := strconv.Atoi(string(h[:n]))
		if err != nil || port < 1 || port > 65535 || strings.Trim(string(h[:n]), "0123456789") != "" {
			break
		}
		return string(h[:n]), nil
	}
	return "", errors.New("invalid cache port")
}
func (s *Service) endpointOwner(name string, r *http.Request) bool {
	if r.URL.Path == "/ca.crl" && !r.URL.IsAbs() && (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.RawQuery == "" {
		return true
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if r.Method == http.MethodConnect || r.URL.IsAbs() {
		token = strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Bearer ")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := strings.CutPrefix(r.URL.Path, "/object/"); ok && !r.URL.IsAbs() {
		token = s.leases[id].token
	}
	g, ok := s.grants[token]
	return ok && g.name == name && time.Now().Before(g.expires) && !s.closed
}

func RunGuestEndpoint(ctx context.Context, control io.ReadWriteCloser) error {
	return runGuestEndpoint(ctx, control, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", cachelink.Endpoint)
	})
}
func runGuestEndpoint(parent context.Context, control io.ReadWriteCloser, dial func(context.Context) (net.Conn, error)) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("guest cache loopback unavailable")
	}
	defer func() { _ = l.Close(); _ = control.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = l.Close(); _ = control.Close() })
	defer stop()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	if _, err := io.WriteString(control, port+"\n"); err != nil {
		return errors.New("cache control unavailable")
	}
	done := make(chan struct{})
	go func() { defer close(done); var b [1]byte; _, _ = control.Read(b[:]); cancel() }()
	var wg sync.WaitGroup
	defer func() { cancel(); _ = control.Close(); <-done; wg.Wait() }()
	for {
		guest, err := l.Accept()
		if err != nil {
			return nil
		}
		wg.Go(func() {
			defer func() { _ = guest.Close() }()
			stopGuest := context.AfterFunc(ctx, func() { _ = guest.Close() })
			defer stopGuest()
			remote, err := dial(ctx)
			if err != nil {
				return
			}
			defer func() { _ = remote.Close() }()
			stopRemote := context.AfterFunc(ctx, func() { _ = remote.Close() })
			defer stopRemote()
			streamrelay.Copy(remote, guest)
		})
	}
}
func GuestEndpoint(ctx context.Context) error { return RunGuestEndpoint(ctx, guestStdio{}) }

// guestStdio is the private command-control capability, not a payload channel.
type guestStdio struct{}

func (guestStdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (guestStdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (guestStdio) Close() error                { return errors.Join(os.Stdin.Close(), os.Stdout.Close()) }
