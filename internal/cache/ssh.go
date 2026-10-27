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
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHBinding comes only from a currently verified owned VM transport. The host
// key must already be pinned by the provider's ordinary bootstrap connection.
type SSHBinding struct{ Address, User, KeyFile, KnownHosts string }

type sshTransport struct {
	client  *ssh.Client
	server  *http.Server
	closing atomic.Bool
	// Requests in progress. A guest deleted before revocation ends its
	// transport while idle; only an ending with work in flight is reported.
	active atomic.Int64
	// active when the SSH socket first failed. x/crypto closes forwarded
	// channels before Client.Wait returns, so a request can observe the loss
	// and finish first; the socket error precedes that closure.
	lostOnce   sync.Once
	lostActive int64
}

func (t *sshTransport) lost() int64 {
	t.lostOnce.Do(func() { t.lostActive = t.active.Load() })
	return t.lostActive
}

// lossConn records the transport's in-flight requests on the SSH socket's
// first read or write error, before the SSH library reacts to it.
type lossConn struct {
	net.Conn
	lost func() int64
}

func (c lossConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.lost()
	}
	return n, err
}

func (c lossConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		c.lost()
	}
	return n, err
}

// SSHLoss records a cache transport's in-flight requests on its SSH socket's
// first failure. Wrap the socket with Conn before the SSH handshake, then pass
// the same SSHLoss to AttachSSHClient. Each SSHLoss serves one transport.
type SSHLoss struct {
	transport *sshTransport
	claimed   atomic.Bool
}

func NewSSHLoss() *SSHLoss { return &SSHLoss{transport: &sshTransport{}} }

func (l *SSHLoss) Conn(c net.Conn) net.Conn { return lossConn{Conn: c, lost: l.transport.lost} }

func (t *sshTransport) serve(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.active.Add(1)
		defer t.active.Add(-1)
		next.ServeHTTP(w, r)
	})
}

// SSH channels do not implement net.Conn deadlines. HTTP CONNECT hijacking
// must interrupt its background read before returning 200; a deadline-capable
// local pipe preserves backpressure without exposing a host TCP listener.
type deadlineListener struct{ net.Listener }

func (l deadlineListener) Accept() (net.Conn, error) {
	channel, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	server, stream := net.Pipe()
	go relay(stream, channel)
	return server, nil
}

// Bound guest-created channels before TLS/header parsing and HTTP dispatch.
// Queueing remains in the SSH library's bounded forwarding queue.
type limitedListener struct {
	net.Listener
	slots    chan struct{}
	done     chan struct{}
	once     sync.Once
	closeErr error
}
type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case <-l.done:
			_ = conn.Close()
			return nil, net.ErrClosed
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close() // Reject excess channels rather than stall SSH dispatch.
		}
	}
}
func (l *limitedListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		// x/crypto's forward dispatcher can hold its registry mutex while
		// enqueueing a channel. Drain pending channels during listener removal,
		// including failed accepts after the SSH socket closes, to let removal
		// acquire that mutex. The transport closes its SSH client first.
		stop, drained := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(drained)
			for {
				conn, _ := l.Listener.Accept()
				if conn != nil {
					_ = conn.Close()
				}
				select {
				case <-stop:
					return
				default:
				}
			}
		}()
		l.closeErr = l.Listener.Close()
		close(stop)
		<-drained
	})
	return l.closeErr
}

func (t *sshTransport) Close() error {
	t.closing.Store(true)
	return errors.Join(t.client.Close(), t.server.Close())
}

func pinnedAlgorithms(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 256<<10 {
		return nil, errors.New("bounded SSH host pins unavailable")
	}
	var algorithms []string
	for len(data) > 0 {
		_, _, key, _, rest, err := ssh.ParseKnownHosts(data)
		if err != nil {
			return nil, errors.New("SSH host pin invalid")
		}
		data = rest
		candidates := []string{key.Type()}
		if key.Type() == ssh.KeyAlgoRSA {
			candidates = []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}
		}
		for _, algo := range candidates {
			if slices.Contains(ssh.SupportedAlgorithms().HostKeys, algo) && !slices.Contains(algorithms, algo) {
				algorithms = append(algorithms, algo)
			}
		}
	}
	if len(algorithms) == 0 {
		return nil, errors.New("supported SSH host pin required")
	}
	return algorithms, nil
}

// AttachSSH serves only the cache HTTP handler through a guest-loopback SSH
// listener. It never forwards guest traffic to host sockets, opens a shell,
// shares a directory, or relaxes NIC isolation. Process loss closes the SSH
// connection; the guest adapter then uses its normal public upstream path.
func (s *Service) AttachSSH(ctx context.Context, name string, b SSHBinding) ([]byte, error) {
	host, _, err := net.SplitHostPort(b.Address)
	u, parseErr := url.Parse(s.url)
	if err != nil || host != "127.0.0.1" || parseErr != nil || u.Hostname() != "127.0.0.1" || b.User == "" {
		return nil, errors.New("cache SSH transport requires owned loopback binding and loopback TLS identity")
	}
	key, err := os.ReadFile(b.KeyFile)
	if err != nil {
		return nil, errors.New("cache SSH key unavailable")
	}
	signer, err := ssh.ParsePrivateKey(key)
	clear(key)
	if err != nil {
		return nil, errors.New("cache SSH key invalid")
	}
	check, err := knownhosts.New(b.KnownHosts)
	if err != nil {
		return nil, errors.New("cache SSH host pin unavailable")
	}
	// OpenSSH and Go can prefer different keys on a multi-key server. Negotiate
	// only algorithms actually recorded by normal bootstrap, then verify the
	// exact hostname/key with knownhosts; never accept a second key implicitly.
	algorithms, err := pinnedAlgorithms(b.KnownHosts)
	if err != nil {
		return nil, err
	}
	socket, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", b.Address)
	if err != nil {
		return nil, errors.New("cache SSH transport unavailable")
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stopCancel()
	_ = socket.SetDeadline(time.Now().Add(15 * time.Second))
	loss := NewSSHLoss()
	conn, channels, requests, err := ssh.NewClientConn(loss.Conn(socket), b.Address, &ssh.ClientConfig{User: b.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: check, HostKeyAlgorithms: algorithms})
	if err != nil {
		_ = socket.Close()
		return nil, errors.New("cache SSH identity or authentication failed")
	}
	client := ssh.NewClient(conn, channels, requests)
	bootstrap, err := s.AttachSSHClient(ctx, name, client, loss)
	_ = socket.SetDeadline(time.Time{})
	return bootstrap, err
}

// AttachSSHClient takes ownership of a dedicated, already-authenticated client
// to a currently verified owned guest whose host key the caller has pinned.
// It closes the client on failure, revocation or service shutdown. Cancellation
// bounds attachment only; a successful transport outlives ctx. The caller must
// not share this client with command sessions or close it after handing it off.
// loss must be the unused SSHLoss whose Conn wrapped the client's socket.
func (s *Service) AttachSSHClient(ctx context.Context, name string, client *ssh.Client, loss *SSHLoss) ([]byte, error) {
	if client == nil {
		return nil, errors.New("cache SSH client unavailable")
	}
	if loss == nil || !loss.claimed.CompareAndSwap(false, true) {
		_ = client.Close()
		return nil, errors.New("cache SSH loss monitor missing or reused")
	}
	transport := loss.transport
	stopCancel := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stopCancel()
	u, err := url.Parse(s.url)
	if ctx.Err() != nil || err != nil || u.Hostname() != "127.0.0.1" {
		_ = client.Close()
		return nil, errors.New("cache SSH attachment requires active context and loopback TLS identity")
	}
	listener, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = client.Close()
		return nil, errors.New("guest loopback cache listener unavailable")
	}
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.Equal(net.ParseIP("127.0.0.1")) || addr.Port < 1 {
		_ = client.Close()
		return nil, errors.New("guest cache listener not loopback")
	}
	bootstrap, err := s.issueAt(name, "https://"+listener.Addr().String(), GrantCapabilities{ReleaseProxy: true})
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	transport.client = client
	server := &http.Server{Handler: transport.serve(s), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: serveTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	transport.server = server
	var issued Bootstrap
	if json.Unmarshal(bootstrap, &issued) != nil {
		clear(bootstrap)
		_ = transport.Close()
		return nil, errors.New("cache bootstrap unavailable")
	}
	s.mu.Lock()
	grant, valid := s.grants[issued.Token]
	if s.closed || !valid || grant.name != name {
		s.mu.Unlock()
		clear(bootstrap)
		_ = transport.Close()
		return nil, errors.New("cache closed during SSH attachment")
	}
	s.transports[name] = transport
	s.mu.Unlock()
	go func() {
		err := client.Wait()
		if active := transport.lost(); active > 0 && !transport.closing.Load() {
			reason, _ := failureDetails(err)
			if reason == "unavailable" {
				reason = "ssh_closed"
			}
			s.log.Warn("cache SSH transport ended during requests", "guest", name, "reason", reason, "active_requests", active)
		}
		_ = server.Close()
	}()
	go func() {
		bounded := &limitedListener{Listener: listener, slots: make(chan struct{}, 64), done: make(chan struct{})}
		_ = server.Serve(tls.NewListener(deadlineListener{bounded}, &tls.Config{Certificates: []tls.Certificate{s.certificate}, MinVersion: tls.VersionTLS12}))
	}()
	return bootstrap, nil
}
