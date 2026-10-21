package cache

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// A real SSH handshake and forwarded-tcpip channels, with no shell/exec or
// general direct forwarding. Keys are synthetic and exist only in t.TempDir.
func cacheSSHFixture(t *testing.T) SSHBinding {
	t.Helper()
	binding, _ := droppableSSHFixture(t)
	return binding
}

// droppableSSHFixture also returns a function that closes every guest-side
// SSH connection, as deleting a guest before revocation does.
func droppableSSHFixture(t *testing.T) (SSHBinding, func()) {
	t.Helper()
	return sshFixture(t, nil)
}

func sshFixture(t *testing.T, beforeForward func()) (SSHBinding, func()) {
	return sshFixtureWithListenerHook(t, beforeForward, nil)
}

func sshFixtureWithListenerHook(t *testing.T, beforeForward, beforeListen func()) (SSHBinding, func()) {
	t.Helper()
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if c.User() != "ciuser" || !bytes.Equal(k.Marshal(), client.PublicKey().Marshal()) {
			return nil, os.ErrPermission
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	secondary, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondarySigner, err := ssh.NewSignerFromKey(secondary)
	if err != nil {
		t.Fatal(err)
	}
	config.AddHostKey(secondarySigner) // Go's default would choose this unpinned key.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var connections []net.Conn
	drop := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range connections {
			_ = c.Close()
		}
	}
	t.Cleanup(func() {
		_ = listener.Close()
		drop()
	})
	go func() {
		for {
			socket, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, socket)
			mu.Unlock()
			go func() {
				defer func() { _ = socket.Close() }()
				conn, channels, requests, err := ssh.NewServerConn(socket, config)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				forwardCtx, cancelForwards := context.WithCancel(context.Background())
				defer cancelForwards()
				go func() {
					for ch := range channels {
						_ = ch.Reject(ssh.Prohibited, "no commands or general forwarding")
					}
				}()
				var forwards []net.Listener
				defer func() {
					for _, l := range forwards {
						_ = l.Close()
					}
				}()
				for req := range requests {
					var bind struct {
						Address string
						Port    uint32
					}
					if req.Type != "tcpip-forward" || ssh.Unmarshal(req.Payload, &bind) != nil || bind.Address != "127.0.0.1" || bind.Port != 0 {
						_ = req.Reply(false, nil)
						continue
					}
					if beforeListen != nil {
						beforeListen()
					}
					remote, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						_ = req.Reply(false, nil)
						continue
					}
					forwards = append(forwards, remote)
					// #nosec G115 -- A successful TCP listener has a 16-bit port.
					port := uint32(remote.Addr().(*net.TCPAddr).Port)
					_ = req.Reply(true, ssh.Marshal(struct{ Port uint32 }{port}))
					go func() {
						for {
							incoming, err := remote.Accept()
							if err != nil {
								return
							}
							// The guest owns accepted sockets even before their SSH
							// channels open. SSH shutdown must close them independently
							// of a delayed or blocked forwarding goroutine.
							stopClose := context.AfterFunc(forwardCtx, func() { _ = incoming.Close() })
							go func() {
								defer stopClose()
								defer func() { _ = incoming.Close() }()
								if beforeForward != nil {
									beforeForward()
								}
								payload := ssh.Marshal(struct {
									Address    string
									Port       uint32
									Origin     string
									OriginPort uint32
								}{"127.0.0.1", port, "127.0.0.1", 1})
								channel, requests, err := conn.OpenChannel("forwarded-tcpip", payload)
								if err != nil {
									return
								}
								defer func() { _ = channel.Close() }()
								go ssh.DiscardRequests(requests)
								done := make(chan struct{})
								go func() { _, _ = io.Copy(channel, incoming); _ = channel.CloseWrite(); close(done) }()
								_, _ = io.Copy(incoming, channel)
								_ = incoming.Close()
								<-done
							}()
						}
					}()
				}
			}()
		}
	}()
	dir := t.TempDir()
	key, err := ssh.MarshalPrivateKey(clientKey, "")
	if err != nil {
		t.Fatal(err)
	}
	b := SSHBinding{Address: listener.Addr().String(), User: "ciuser", KeyFile: filepath.Join(dir, "key"), KnownHosts: filepath.Join(dir, "known_hosts")}
	if err = os.WriteFile(b.KeyFile, pem.EncodeToMemory(key), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(b.KnownHosts, []byte(knownhosts.Line([]string{b.Address}, host.PublicKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return b, drop
}

func sshCacheClient(t *testing.T, s *Service, name string, binding SSHBinding) (Bootstrap, *http.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := s.AttachSSH(ctx, name, binding)
	if err != nil {
		t.Fatal(err)
	}
	var b Bootstrap
	if err = json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(b.CA))
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	return b, client
}

func TestSSHCacheColdWarmPerGuestLeaseAndRevocation(t *testing.T) {
	var gets atomic.Int32
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"same"`)
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodGet {
			gets.Add(1)
			_, _ = io.WriteString(w, "payload")
		}
	}))
	defer backend.Close()
	s, _, _ := testService(t, backend)
	b, client := sshCacheClient(t, s, "guest", cacheSSHFixture(t))
	if b.URL == s.url {
		t.Fatal("bootstrap exposed host socket instead of guest SSH listener")
	}
	for range 2 {
		lease := makeLease(t, b, client, backend.URL+"/archive")
		if !strings.HasPrefix(lease, b.URL+"/object/") {
			t.Fatal("lease escaped guest transport")
		}
		response, err := client.Get(lease)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(data) != "payload" {
			t.Fatal("archive changed in SSH transport")
		}
	}
	if gets.Load() != 1 {
		t.Fatal("second guest read did not hit local store")
	}
	s.Revoke("guest")
	client.CloseIdleConnections()
	if response, err := client.Get(b.URL + "/lease"); err == nil {
		_ = response.Body.Close()
		t.Fatal("revoked guest listener survived")
	}
}

func TestSSHCacheRequiresPriorPinnedHostIdentity(t *testing.T) {
	backend := httptest.NewTLSServer(http.NotFoundHandler())
	defer backend.Close()
	s, _, _ := testService(t, backend)
	b := cacheSSHFixture(t)
	if err := os.WriteFile(b.KnownHosts, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AttachSSH(context.Background(), "guest", b); err == nil {
		t.Fatal("unrecorded host key accepted")
	}
	b.Address = "10.0.0.1:22"
	if _, err := s.AttachSSH(context.Background(), "guest", b); err == nil {
		t.Fatal("non-loopback SSH binding accepted")
	}
}

func authenticatedCacheClient(t *testing.T, b SSHBinding) (*ssh.Client, *SSHLoss) {
	t.Helper()
	key, err := os.ReadFile(b.KeyFile)
	if err != nil {
		t.Fatal("client key unavailable")
	}
	signer, err := ssh.ParsePrivateKey(key)
	clear(key)
	if err != nil {
		t.Fatal("client key invalid")
	}
	check, err := knownhosts.New(b.KnownHosts)
	if err != nil {
		t.Fatal(err)
	}
	algorithms, err := pinnedAlgorithms(b.KnownHosts)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.DialTimeout("tcp", b.Address, 5*time.Second)
	if err != nil {
		t.Fatal("fixture SSH transport unavailable")
	}
	loss := NewSSHLoss()
	conn, channels, requests, err := ssh.NewClientConn(loss.Conn(socket), b.Address, &ssh.ClientConfig{User: b.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: check, HostKeyAlgorithms: algorithms, Timeout: 5 * time.Second})
	if err != nil {
		_ = socket.Close()
		t.Fatal("fixture SSH authentication failed")
	}
	client := ssh.NewClient(conn, channels, requests)
	t.Cleanup(func() { _ = client.Close() })
	return client, loss
}

func TestSSHCacheCallerProvidedClientOwnership(t *testing.T) {
	for _, mode := range []string{"revoke", "shutdown", "canceled", "closed-service"} {
		t.Run(mode, func(t *testing.T) {
			backend := httptest.NewTLSServer(http.NotFoundHandler())
			defer backend.Close()
			s, _, _ := testService(t, backend)
			s.EnableReleaseProxy()
			binding := cacheSSHFixture(t)
			client, loss := authenticatedCacheClient(t, binding)
			independent, _ := authenticatedCacheClient(t, binding)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			if mode == "closed-service" {
				s.Close()
			}
			data, err := s.AttachSSHClient(ctx, "guest", client, loss)
			defer clear(data)
			if mode == "canceled" || mode == "closed-service" {
				if err == nil {
					t.Fatal("attachment accepted after cancellation or shutdown")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				cancel() // Successful attachment must outlive its setup context.
				var b Bootstrap
				if json.Unmarshal(data, &b) != nil {
					t.Fatal("invalid bootstrap")
				}
				roots := x509.NewCertPool()
				roots.AppendCertsFromPEM([]byte(b.CA))
				httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, Timeout: 5 * time.Second}
				defer httpClient.CloseIdleConnections()
				response, err := httpClient.Get(b.URL + "/ca.crl")
				if err != nil {
					t.Fatal("caller-provided transport unavailable")
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Fatal("caller-provided transport did not serve public PKI")
				}
				if mode == "revoke" {
					s.Revoke("guest")
				} else {
					s.Close()
				}
			}
			ended := make(chan struct{})
			go func() { _ = client.Wait(); close(ended) }()
			select {
			case <-ended:
			case <-time.After(5 * time.Second):
				t.Fatal("owned client survived attachment failure or revocation")
			}
			if _, _, err := independent.SendRequest("keepalive@bivouac", true, nil); err != nil {
				t.Fatal("cache closure closed independent command client")
			}
		})
	}
}

func TestSSHCacheCallerClientCancellationDuringAttachment(t *testing.T) {
	requested, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	binding, _ := sshFixtureWithListenerHook(t, nil, func() {
		close(requested)
		<-release
	})
	backend := httptest.NewTLSServer(http.NotFoundHandler())
	defer backend.Close()
	s, _, _ := testService(t, backend)
	client, loss := authenticatedCacheClient(t, binding)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ended := make(chan error, 1)
	go func() {
		data, err := s.AttachSSHClient(ctx, "guest", client, loss)
		clear(data)
		ended <- err
	}()
	select {
	case <-requested:
	case <-time.After(5 * time.Second):
		t.Fatal("guest listener was not requested")
	}
	cancel()
	select {
	case err := <-ended:
		if err == nil {
			t.Fatal("canceled attachment succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not close blocked client")
	}
	s.mu.Lock()
	attached := len(s.transports)
	s.mu.Unlock()
	if attached != 0 {
		t.Fatal("canceled attachment retained transport")
	}
}

func TestSSHRevocationClosesActiveAndQueuedChannels(t *testing.T) {
	backend := httptest.NewTLSServer(http.NotFoundHandler())
	defer backend.Close()
	s, _, _ := testService(t, backend)
	b, _ := sshCacheClient(t, s, "guest", cacheSSHFixture(t))
	endpoint, err := url.Parse(b.URL)
	if err != nil {
		t.Fatal(err)
	}
	var sockets []net.Conn
	defer func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
	}()
	// Exceed the 64 accepted-channel ceiling without sending TLS headers.
	for range 67 {
		socket, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		sockets = append(sockets, socket)
	}
	s.Revoke("guest")
	for _, socket := range sockets {
		_ = socket.SetReadDeadline(time.Now().Add(3 * time.Second))
		var byte [1]byte
		var timeout net.Error
		if _, err = socket.Read(byte[:]); err == nil {
			t.Fatal("revoked guest channel still readable")
		} else if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("queued guest channel survived revocation")
		}
	}
}

func TestSSHRevocationClosesChannelsAwaitingForward(t *testing.T) {
	accepted, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	binding, _ := sshFixture(t, func() {
		close(accepted)
		<-release // Revoke after TCP accept but before SSH channel creation.
	})
	backend := httptest.NewTLSServer(http.NotFoundHandler())
	defer backend.Close()
	s, _, _ := testService(t, backend)
	b, _ := sshCacheClient(t, s, "guest", binding)
	endpoint, err := url.Parse(b.URL)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = socket.Close() }()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture did not accept guest socket")
	}
	s.Revoke("guest")
	_ = socket.SetReadDeadline(time.Now().Add(3 * time.Second))
	var data [1]byte
	var timeout net.Error
	if _, err = socket.Read(data[:]); err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
		t.Fatal("guest socket awaiting SSH forwarding survived revocation")
	}
}

func TestSSHReleaseCacheAndDirectFallback(t *testing.T) {
	var gets atomic.Int32
	s, _, _ := proxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"release"`)
		w.Header().Set("Content-Length", "7")
		w.Header().Set("Content-Disposition", "attachment")
		if r.Method == http.MethodGet {
			gets.Add(1)
			_, _ = io.WriteString(w, "payload")
		}
	}))
	b, crlClient := sshCacheClient(t, s, "guest", cacheSSHFixture(t))
	proxy, err := NewGuestProxy(b)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	bridge := httptest.NewServer(proxy)
	defer bridge.Close()
	endpoint, _ := url.Parse(bridge.URL)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(b.CA))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(endpoint), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	var previousCRL *x509.RevocationList
	for range 2 {
		response, err := client.Get("https://github.com/example/deps/releases/download/v1/asset")
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(data) != "payload" {
			t.Fatal("release bytes changed")
		}
		leaf := response.TLS.PeerCertificates[0]
		if len(leaf.CRLDistributionPoints) != 1 || leaf.CRLDistributionPoints[0] != b.URL+"/ca.crl" {
			t.Fatal("revocation endpoint escaped the guest SSH transport")
		}
		crlResponse, err := crlClient.Get(leaf.CRLDistributionPoints[0])
		if err != nil {
			t.Fatal(err)
		}
		crlBytes, err := io.ReadAll(crlResponse.Body)
		_ = crlResponse.Body.Close()
		if err != nil || crlResponse.StatusCode != http.StatusOK || crlResponse.Header.Get("Content-Type") != "application/pkix-crl" {
			t.Fatal("signed revocation list unavailable")
		}
		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			t.Fatal(err)
		}
		if crl.CheckSignatureFrom(response.TLS.PeerCertificates[1]) != nil || len(crl.RevokedCertificateEntries) != 0 || time.Now().Before(crl.ThisUpdate) || !time.Now().Before(crl.NextUpdate) {
			t.Fatal("invalid proxy revocation evidence")
		}
		if previousCRL != nil && crl.Number.Cmp(previousCRL.Number) <= 0 {
			t.Fatal("long-running service retained an expired revocation list")
		}
		previousCRL = crl
		s.mu.Lock()
		s.crlExpires = time.Now().Add(-time.Minute)
		s.mu.Unlock()
	}
	if gets.Load() != 1 {
		t.Fatal("release did not hit local cache over SSH")
	}
	s.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "direct") }))
	defer upstream.Close()
	response, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(data) != "direct" {
		t.Fatal("guest proxy did not fall back after SSH/cache loss")
	}
}

func TestSSHTransportLossIsReportedOnlyDuringRequests(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"same"`)
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodGet {
			started <- struct{}{}
			<-release
		}
	}))
	defer backend.Close()
	defer close(release)
	s, direct, directClient := testService(t, backend)
	var logs syncBuffer
	s.log = slog.New(slog.NewTextHandler(&logs, nil))
	source := backend.URL + "/archive?sig=synthetic-secret"
	get := func(c *http.Client, lease string) {
		if response, err := c.Get(lease); err == nil {
			_ = response.Body.Close()
		}
	}
	for _, busy := range []bool{false, true} {
		binding, drop := droppableSSHFixture(t)
		b, client := sshCacheClient(t, s, "guest-name", binding)
		if busy {
			// A direct guest's fill holds upstream. The SSH guest waits on that
			// fill and leaves as soon as its transport ends, which races the
			// transport's own loss report.
			go get(directClient, makeLease(t, direct, directClient, source))
			<-started
			// The lease reply is flushed after its handler returns, so the only
			// request counted below is the object read.
			lease := makeLease(t, b, client, source)
			go get(client, lease)
			s.mu.Lock()
			transport := s.transports["guest-name"].(*sshTransport)
			s.mu.Unlock()
			for deadline := time.Now().Add(5 * time.Second); transport.active.Load() == 0; time.Sleep(time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatal("SSH request did not start")
				}
			}
		}
		drop()
		if !busy {
			time.Sleep(300 * time.Millisecond) // Give an unwanted report time to appear.
		}
		deadline := time.Now().Add(5 * time.Second)
		for busy && !strings.Contains(logs.String(), "transport ended") && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		reported := strings.Contains(logs.String(), "transport ended")
		if reported != busy {
			t.Fatalf("busy=%v reported=%v", busy, reported)
		}
	}
	text := logs.String()
	if !strings.Contains(text, "guest=guest-name") || !strings.Contains(text, "active_requests=1") || strings.Contains(text, "synthetic-secret") {
		t.Fatal("transport loss diagnostic", text)
	}
}

// syncBuffer collects logs written by transport goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestAttachSSHClientRequiresItsOwnLossMonitor(t *testing.T) {
	binding := cacheSSHFixture(t)
	backend := httptest.NewTLSServer(http.NotFoundHandler())
	defer backend.Close()
	s, _, _ := testService(t, backend)
	client, _ := authenticatedCacheClient(t, binding)
	if _, err := s.AttachSSHClient(t.Context(), "guest", client, nil); err == nil {
		t.Fatal("attachment accepted without a loss monitor")
	}
	if _, _, err := client.SendRequest("keepalive@bivouac", true, nil); err == nil {
		t.Fatal("refused attachment left its client open")
	}
	first, loss := authenticatedCacheClient(t, binding)
	data, err := s.AttachSSHClient(t.Context(), "guest", first, loss)
	clear(data)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := authenticatedCacheClient(t, binding)
	if _, err := s.AttachSSHClient(t.Context(), "other", second, loss); err == nil {
		t.Fatal("attachment accepted a reused loss monitor")
	}
}
