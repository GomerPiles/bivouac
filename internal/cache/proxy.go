package cache

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Only these hosts are decrypted. Other public destinations use opaque tunnels.
// The guest root's name constraints permit exactly these DNS names.
func interceptedHosts() []string {
	return []string{"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
}

func releaseHost(host string) bool { return slices.Contains(interceptedHosts(), host) }

type releaseProxy struct {
	// enabled may be set after Serve starts; handlers read it concurrently.
	enabled atomic.Bool
	root    tls.Certificate
	ca      *x509.Certificate
	signer  crypto.Signer
}

func newReleaseProxy(root tls.Certificate) (*releaseProxy, error) {
	ca, err := x509.ParseCertificate(root.Certificate[0])
	if err != nil {
		return nil, err
	}
	signer, ok := root.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("invalid proxy identity")
	}
	return &releaseProxy{root: root, ca: ca, signer: signer}, nil
}

// Each certificate points to the granting guest's cache endpoint, including
// its SSH listener. Schannel can check revocation without disabling TLS checks
// or requiring a guest-to-host NIC exception. Keys live only for this tunnel.
func (p *releaseProxy) leaf(host, endpoint string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: p.ca.NotBefore, NotAfter: p.ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CRLDistributionPoints: []string{endpoint + "/ca.crl"}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, p.ca, &key.PublicKey, p.signer)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, p.root.Certificate[0]}, PrivateKey: key}, nil
}

// This public PKI object contains no capability, archive, or private key.
// Renew before expiration so a long-lived manager remains usable by Schannel.
func (s *Service) serveRevocationList(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	now := time.Now().UTC()
	if s.crlExpires.Before(now.Add(5 * time.Minute)) {
		expires := now.Add(time.Hour)
		data, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(now.UnixNano()), ThisUpdate: now.Add(-time.Minute), NextUpdate: expires}, s.proxy.ca, s.proxy.signer)
		if err != nil {
			s.mu.Unlock()
			http.Error(w, "proxy revocation list unavailable", http.StatusServiceUnavailable)
			return
		}
		s.crl, s.crlExpires = data, expires
	}
	data := s.crl
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(data)
	}
}

func (s *Service) authorized(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[token]
	return ok && time.Now().Before(g.expires)
}

func (s *Service) serveProxy(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Bearer ")
	if !s.authorized(token) {
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method != http.MethodConnect {
		s.forward(w, r, token, "")
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	host = strings.ToLower(host)
	if err != nil || port != "443" || strings.ContainsAny(host, "@/\\") {
		http.Error(w, "unsupported destination", http.StatusForbidden)
		return
	}
	var upstream net.Conn
	if !releaseHost(host) {
		// Use the same public-only DNS policy as the cache client; no host LAN access.
		transport := s.client.Transport.(*http.Transport)
		upstream, err = transport.DialContext(r.Context(), "tcp", net.JoinHostPort(host, port))
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer func() { _ = upstream.Close() }()
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy unavailable", http.StatusBadGateway)
		return
	}
	conn, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(); s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
	s.mu.Lock()
	g, valid := s.grants[token]
	count := 0
	for _, owner := range s.connections {
		if owner == token {
			count++
		}
	}
	if !valid || time.Now().After(g.expires) || count >= 32 {
		s.mu.Unlock()
		_, _ = buffer.WriteString("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
		_ = buffer.Flush()
		return
	}
	s.connections[conn] = token
	_ = conn.SetDeadline(g.expires)
	s.mu.Unlock()
	_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if buffer.Flush() != nil {
		return
	}
	buffered := &readerConn{Conn: conn, reader: buffer.Reader}
	if upstream != nil {
		relay(buffered, upstream)
		return
	}
	leaf, err := s.proxy.leaf(host, g.url)
	if err != nil {
		return
	}
	secured := tls.Server(buffered, &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12})
	handshake, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	err = secured.HandshakeContext(handshake)
	cancel()
	if err != nil {
		return
	}
	listener := &oneListener{conn: secured, done: make(chan struct{})}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) { s.forward(w, request, token, host) }), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	_ = server.Serve(listener)
}

type readerConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// A listener serving exactly one decrypted connection. Serve remains alive until
// that connection closes, so the CONNECT handler owns its complete lifetime.
type oneListener struct {
	conn     net.Conn
	accepted bool
	done     chan struct{}
	once     sync.Once
}
type closingConn struct {
	net.Conn
	listener *oneListener
}

func (c *closingConn) Close() error {
	e := c.Conn.Close()
	c.listener.once.Do(func() { close(c.listener.done) })
	return e
}
func (l *oneListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return &closingConn{Conn: l.conn, listener: l}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneListener) Close() error   { l.once.Do(func() { close(l.done) }); return l.conn.Close() }
func (l *oneListener) Addr() net.Addr { return l.conn.LocalAddr() }

func relay(a, b net.Conn) {
	done := make(chan struct{})
	go func() { _, _ = io.Copy(a, b); _ = a.Close(); _ = b.Close(); close(done) }()
	_, _ = io.Copy(b, a)
	_ = a.Close()
	_ = b.Close()
	<-done
}

func cleanHeaders(h http.Header) {
	for _, name := range strings.Split(h.Get("Connection"), ",") {
		h.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(name)
	}
}

func (s *Service) forward(w http.ResponseWriter, r *http.Request, token, interceptedHost string) {
	if !s.authorized(token) {
		http.Error(w, "expired proxy capability", http.StatusForbidden)
		return
	}
	request := r.Clone(r.Context())
	request.URL = new(url.URL)
	*request.URL = *r.URL
	if interceptedHost != "" {
		// Reject authority changes inside a CONNECT tunnel, including absolute URLs.
		if !sameAuthority(r.Host, interceptedHost) || (r.URL.IsAbs() && (r.URL.Scheme != "https" || !sameAuthority(r.URL.Host, interceptedHost))) {
			http.Error(w, "invalid authority", http.StatusForbidden)
			return
		}
		request.URL.Scheme = "https"
		request.URL.Host = interceptedHost
	}
	u := request.URL
	port := u.Port()
	validTransport := u.Scheme == "https" && (port == "" || port == "443") || u.Scheme == "http" && (port == "" || port == "80")
	if u.User != nil || u.Fragment != "" || u.Hostname() == "" || !validTransport {
		http.Error(w, "unsupported destination", http.StatusForbidden)
		return
	}
	request.RequestURI = ""
	request.Host = u.Host
	cleanHeaders(request.Header)
	if s.cacheRelease(w, request, token) {
		return
	}
	response, err := s.client.Transport.RoundTrip(request)
	if err != nil {
		if r.Method == http.MethodGet {
			s.recordTransfer(token, true, cacheBypass, 0, true)
		}
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	cleanHeaders(response.Header)
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(response.StatusCode)
	n, copyErr := io.Copy(w, response.Body)
	if r.Method == http.MethodGet {
		s.recordTransfer(token, true, cacheBypass, n, copyErr != nil || response.StatusCode >= 400)
	}
}

func sameAuthority(authority, host string) bool {
	return strings.EqualFold(authority, host) || strings.EqualFold(authority, host+":443")
}

func releaseRequest(r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.Body != nil && r.ContentLength != 0 {
		return false
	}
	for _, header := range []string{"Authorization", "Cookie", "Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "If-Range", "Cache-Control"} {
		if r.Header.Get(header) != "" {
			return false
		}
	}
	host := strings.ToLower(r.URL.Hostname())
	if host == "github.com" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		return len(parts) >= 6 && parts[2] == "releases" && parts[3] == "download" && r.URL.RawQuery == ""
	}
	return (host == "release-assets.githubusercontent.com" || host == "objects.githubusercontent.com") && strings.HasPrefix(r.URL.Path, "/github-production-release-asset") && r.URL.RawQuery != ""
}

func reusableResponse(r *http.Response, limit int64) bool {
	control := strings.ToLower(r.Header.Get("Cache-Control"))
	etag := r.Header.Get("ETag")
	return r.StatusCode == 200 && r.ContentLength >= 0 && r.ContentLength <= limit && etag != "" && !strings.HasPrefix(etag, "W/") && r.Header.Get("Vary") == "" && r.Header.Get("Set-Cookie") == "" && r.Header.Get("Content-Encoding") == "" && !strings.Contains(control, "private") && !strings.Contains(control, "no-store")
}

func (s *Service) cacheRelease(w http.ResponseWriter, r *http.Request, token string) bool {
	if !releaseRequest(r) {
		return false
	}
	head := r.Clone(r.Context())
	head.Method = http.MethodHead
	head.Body = nil
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	response, err := s.client.Do(head.WithContext(ctx)) // #nosec G704 -- release host/path admission above; publicClient rejects private DNS targets and unsafe redirects.
	if err != nil {
		reason, _ := failureDetails(upstreamFailure(err))
		s.log.Info("release cache bypass", "reason", reason)
		return false
	}
	_ = response.Body.Close()
	if !reusableResponse(response, s.store.maxObject) {
		s.log.Info("release cache bypass", "reason", "upstream_identity_or_policy", "status", response.StatusCode)
		return false
	}
	// Validate upstream on every request; exclude rotating URL credentials from
	// identity. A fresh ETag changes the key even if a release asset is replaced.
	source := response.Request.URL
	etag := response.Header.Get("ETag")
	key := "release:" + source.Host + source.EscapedPath() + "\x00" + etag + "\x00" + strconv.FormatInt(response.ContentLength, 10)
	size := response.ContentLength
	label := s.store.label(key)
	cleanHeaders(response.Header)
	controller := http.NewResponseController(w)
	var tee *streamTee
	object, hit, err := s.store.Get(r.Context(), key, size, func(_ context.Context, out io.Writer) error {
		// This guest started the fill: it receives the bytes as they arrive.
		tee = &streamTee{store: out, open: func() io.Writer {
			for key, values := range response.Header {
				w.Header()[key] = values
			}
			w.WriteHeader(http.StatusOK)
			return w
		}, deadline: func() { _ = controller.SetWriteDeadline(time.Now().Add(s.fillIdle)) }}
		get := r.Clone(context.Background())
		get.URL = source
		get.Host = source.Host
		err := s.download(get, label, etag, size, func(fetched *http.Response) error {
			if !reusableResponse(fetched, s.store.maxObject) || fetched.Header.Get("ETag") != etag || fetched.ContentLength != size {
				return &fault{reason: "upstream_identity_or_policy", status: fetched.StatusCode}
			}
			return nil
		}, tee)
		if err == nil && tee.storeErr != nil {
			err = tee.storeErr
		}
		return err
	})
	if tee.started() {
		// The response is committed: a failed fill ends it early, as a failed
		// direct download would.
		if object != nil {
			_ = object.Close()
		}
		delivered := tee.delivered
		if err != nil {
			reason, status := failureDetails(err)
			s.log.Warn("cache fill unavailable", "kind", "github_release", "object", label, "reason", reason, "status", status, "bytes", size, "delivered_bytes", delivered)
		} else {
			s.log.Info("cache object served", "kind", "github_release", "object", label, "hit", false, "bytes", size)
			if tee.clientErr != nil || delivered != size {
				s.log.Warn("cache response incomplete", "kind", "github_release", "object", label, "reason", deliveryFailure(tee.clientErr), "expected_bytes", size, "delivered_bytes", delivered)
			}
		}
		s.recordTransfer(token, true, cacheMiss, delivered, err != nil || tee.clientErr != nil || delivered != size)
		return true
	}
	if err != nil && r.Context().Err() != nil {
		// This guest left while another request's fill ran; the fill continues.
		s.log.Info("cache reader left during fill", "kind", "github_release", "object", label)
		return true
	}
	if err != nil {
		reason, status := failureDetails(err)
		s.log.Info("release cache bypass", "object", label, "reason", reason, "status", status, "bytes", size)
		return false
	}
	defer func() { _ = object.Close() }()
	// Preserve the caller-visible response metadata; no header/URL is persisted.
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	s.log.Info("cache object served", "kind", "github_release", "object", label, "hit", hit, "bytes", size)
	w.WriteHeader(http.StatusOK)
	n, copyErr := io.Copy(w, object)
	if copyErr != nil || n != size {
		reason := deliveryFailure(copyErr)
		if r.Context().Err() != nil {
			reason = deliveryFailure(r.Context().Err())
		}
		s.log.Warn("cache response incomplete", "kind", "github_release", "object", label, "reason", reason, "expected_bytes", size, "delivered_bytes", n)
	}
	outcome := cacheMiss
	if hit {
		outcome = cacheHit
	}
	s.recordTransfer(token, true, outcome, n, copyErr != nil || n != response.ContentLength)
	return true
}
