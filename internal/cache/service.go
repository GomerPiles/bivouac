package cache

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GomerPiles/bivouac/internal/macnetwork"
)

// Bootstrap is delivered privately to one guest, never to state or diagnostics.
type Bootstrap struct {
	URL           string `json:"url"`
	RevocationURL string `json:"revocation_url,omitempty"`
	Token         string `json:"token"`
	CA            string `json:"ca"`
	ReleaseProxy  bool   `json:"release_proxy"`
	StoreUploads  bool   `json:"store_uploads"`
}
type grant struct {
	summary Summary
	name    string
	expires time.Time
	url     string
	crlURL  string
}
type lease struct {
	token, upstream, key, etag string
	size                       int64
	expires                    time.Time
}

// Service owns a TLS listener, short-lived guest capabilities, and bounded storage.
// Metadata stays on GitHub; only authorized archive bytes pass here.
type Service struct {
	endpointLimit int
	macPolicy     *macnetwork.Cache
	summary       Summary
	mu            sync.Mutex
	store         *Store
	client        *http.Client
	log           *slog.Logger
	url, ca       string
	server        *http.Server
	grants        map[string]grant
	leases        map[string]lease
	uploads       map[string]*uploadLease
	ttl           time.Duration
	validate      func(*url.URL) bool
	proxy         *releaseProxy
	connections   map[net.Conn]string
	certificate   tls.Certificate
	transports    map[string]io.Closer
	closed        bool
	storing       atomic.Bool
	work          context.Context // Canceled by Close; owns fills and upload commits.
	stopWork      context.CancelFunc
	held          sync.WaitGroup // Work with store files open: fills, readers, relays and commits.
	fillIdle      time.Duration  // An upstream attempt that receives nothing for this long ends.
	crl           []byte
	crlExpires    time.Time
}

// serveTimeout bounds writing one response. A listener's WriteTimeout starts
// before a fill, so object responses restart this bound once bytes are ready.
const serveTimeout = 15 * time.Minute

func randomToken() string {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}

// Start binds one authenticated endpoint. host is the address reachable from guests.
// TLS private keys and capabilities exist only in memory and rotate after restart.
func Start(dir, listen, host string, maxBytes, maxObject int64, ttl time.Duration, logger *slog.Logger) (*Service, error) {
	store, err := Open(dir, maxBytes, maxObject, logger)
	if err != nil {
		return nil, err
	}
	certificate, ca, err := certificate(host)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, errors.New("listen for cache service")
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	s := &Service{store: store, client: publicClient(), log: logger, url: "https://" + net.JoinHostPort(host, port), ca: ca, grants: map[string]grant{}, leases: map[string]lease{}, uploads: map[string]*uploadLease{}, connections: map[net.Conn]string{}, ttl: ttl, validate: allowedURL, fillIdle: time.Minute}
	s.work, s.stopWork = context.WithCancel(context.Background())
	s.certificate = certificate
	s.transports = map[string]io.Closer{}
	s.proxy, err = newReleaseProxy(certificate)
	if err != nil {
		s.stopWork()
		_ = listener.Close()
		return nil, err
	}
	s.server = &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: serveTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	go func() {
		_ = s.server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}))
	}()
	logger.Info("cache service started", "port", port, "max_bytes", maxBytes, "max_object_bytes", maxObject)
	return s, nil
}

func certificate(host string) (tls.Certificate, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "bivouac guest cache"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	// The root is installed in guest trust stores, so constrain what it can
	// vouch for: the intercepted GitHub hosts (and, per RFC 5280, their
	// subdomains) plus this service's own address.
	// The extension stays non-critical for verifiers without constraint support;
	// Go, OpenSSL, Apple and CryptoAPI enforce it. CRL distribution points are
	// not names, so Schannel revocation checks against /ca.crl are unaffected.
	template.PermittedDNSDomains = interceptedHosts()
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
		if v4 := ip.To4(); v4 != nil {
			template.PermittedIPRanges = []*net.IPNet{{IP: v4, Mask: net.CIDRMask(32, 32)}}
		} else {
			template.PermittedIPRanges = []*net.IPNet{{IP: ip, Mask: net.CIDRMask(128, 128)}}
		}
	} else {
		template.DNSNames = []string{host}
		template.PermittedDNSDomains = append(template.PermittedDNSDomains, host)
		template.ExcludedIPRanges = []*net.IPNet{{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}, {IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pair, err := tls.X509KeyPair(cert, private)
	return pair, string(cert), err
}

// Issue rotates a guest's capability if its bootstrap is retried.
func (s *Service) Issue(name string) ([]byte, error) {
	return s.issueAt(name, s.url)
}
func (s *Service) issueAt(name, endpoint string) ([]byte, error) {
	s.Revoke(name)
	token := randomToken()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errors.New("cache service closed")
	}
	s.grants[token] = grant{name: name, expires: time.Now().Add(s.ttl), url: endpoint, crlURL: endpoint + "/ca.crl"}
	s.mu.Unlock()
	return json.Marshal(Bootstrap{URL: endpoint, Token: token, CA: s.ca, ReleaseProxy: s.proxy.enabled.Load(), StoreUploads: s.storing.Load()})
}
func (s *Service) Revoke(name string) {
	var abandoned []*uploadLease
	s.mu.Lock()
	transport := s.transports[name]
	delete(s.transports, name)
	for token, g := range s.grants {
		if g.name == name || time.Now().After(g.expires) {
			delete(s.grants, token)
			for conn, owner := range s.connections {
				if owner == token {
					_ = conn.Close()
					delete(s.connections, conn)
				}
			}
			for id, l := range s.leases {
				if l.token == token {
					delete(s.leases, id)
				}
			}
			for id, u := range s.uploads {
				if u.token == token {
					delete(s.uploads, id)
					abandoned = append(abandoned, u)
				}
			}
		}
	}
	s.mu.Unlock()
	for _, u := range abandoned {
		u.abandon("revoked")
	}
	if len(abandoned) > 0 {
		s.log.Info("cache uploads abandoned", "reason", "revoked", "uploads", len(abandoned))
	}
	if transport != nil {
		_ = transport.Close()
	}
}
func (s *Service) Close() {
	_ = s.server.Close()
	s.mu.Lock()
	s.closed = true
	s.stopWork()
	transports := s.transports
	s.transports = map[string]io.Closer{}
	for conn := range s.connections {
		_ = conn.Close()
	}
	uploads := s.uploads
	s.uploads = map[string]*uploadLease{}
	s.mu.Unlock()
	for _, transport := range transports {
		_ = transport.Close()
	}
	for _, u := range uploads {
		u.abandon("shutdown")
	}
	if len(uploads) > 0 {
		s.log.Info("cache uploads abandoned", "reason", "shutdown", "uploads", len(uploads))
	}
	s.held.Wait()
	s.LogSummary()
}

// hold registers work that opens store files, so Close joins it before the
// store directory can be reused or removed. It fails once Close has begun.
func (s *Service) hold() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.held.Add(1)
	}
	return !s.closed
}

// EnableReleaseProxy is configured before attaching this service to providers.
// It is safe while the listener is already serving.
func (s *Service) EnableReleaseProxy() {
	s.proxy.enabled.Store(true)
	s.log.Info("optional GitHub release proxy enabled")
}

// GuestUnavailable records only the owned name, never bootstrap or tool output.
func (s *Service) GuestUnavailable(name string) {
	s.log.Warn("guest cache setup unavailable", "guest", name)
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/metrics" && !r.URL.IsAbs() && r.URL.RawQuery == "" {
		s.serveMetrics(w, r)
		return
	}
	if s.proxy.enabled.Load() && r.URL.Path == "/ca.crl" && r.URL.RawQuery == "" && !r.URL.IsAbs() && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		s.serveRevocationList(w, r)
		return
	}
	if s.proxy.enabled.Load() && (r.Method == http.MethodConnect || r.URL.IsAbs()) {
		s.serveProxy(w, r)
		return
	}
	if r.URL.Path == "/lease" && r.Method == http.MethodPost {
		s.createLease(w, r)
		return
	}
	if r.URL.Path == "/upload" && r.Method == http.MethodPost {
		s.createUpload(w, r)
		return
	}
	if id, ok := strings.CutPrefix(r.URL.Path, "/upload/"); ok && !r.URL.IsAbs() {
		s.relayUpload(w, r, id)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/object/")
	if r.URL.Path != "/object/"+id || id == "" || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	l, ok := s.leases[id]
	g, valid := s.grants[l.token]
	s.mu.Unlock()
	if !ok || !valid || time.Now().After(l.expires) || time.Now().After(g.expires) {
		http.Error(w, "expired cache lease", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodHead {
		// Metadata comes from the lease's upstream HEAD: no fill and no hashing.
		s.objectHeaders(w, l)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", strconv.FormatInt(l.size, 10))
		w.WriteHeader(http.StatusOK)
		return
	}
	if !s.hold() {
		http.Error(w, "cache closed", http.StatusServiceUnavailable)
		return
	}
	defer s.held.Done()
	label := s.store.label(l.key)
	measured := &transferWriter{ResponseWriter: w, status: http.StatusOK}
	controller := http.NewResponseController(w)
	var tee *streamTee
	f, hit, err := s.store.Get(r.Context(), l.key, l.size, func(_ context.Context, out io.Writer) error {
		if plainGet(r) {
			// This guest started the fill: it receives the bytes as they arrive.
			tee = &streamTee{store: out, open: func() io.Writer {
				s.objectHeaders(w, l)
				w.Header().Set("Accept-Ranges", "bytes")
				w.Header().Set("Content-Length", strconv.FormatInt(l.size, 10))
				measured.WriteHeader(http.StatusOK)
				return measured
			}, deadline: func() { _ = controller.SetWriteDeadline(time.Now().Add(s.fillIdle)) }, flush: controller.Flush}
			out = tee
		}
		if err := s.fetch(l, label, out); err != nil {
			return err
		}
		if tee != nil && tee.storeErr != nil {
			return tee.storeErr
		}
		return nil
	})
	if tee.started() {
		s.finishStream(l, label, f, err, tee, measured)
		return
	}
	if err != nil && r.Context().Err() != nil {
		// This guest left while another request's fill ran; the fill continues.
		s.log.Info("cache reader left during fill", "kind", "actions_archive", "object", label)
		return
	}
	// The listener's write timeout started before the fill. Bound only serving.
	_ = controller.SetWriteDeadline(time.Now().Add(serveTimeout))
	if err != nil {
		reason, status := failureDetails(err)
		s.log.Warn("cache fill unavailable", "kind", "actions_archive", "object", label, "reason", reason, "status", status, "bytes", l.size)
		s.recordTransfer(l.token, false, cacheBypass, 0, true)
		// The original signed URL is a GitHub-issued capability. Redirect remains
		// authorized by the upstream; no local object is exposed after a failed fill.
		w.Header().Set("Location", l.upstream)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
	defer func() { _ = f.Close() }()
	s.objectHeaders(w, l)
	s.log.Info("cache object served", "kind", "actions_archive", "object", label, "hit", hit, "bytes", l.size)
	http.ServeContent(measured, r, "archive", time.Time{}, f)
	outcome := cacheMiss
	if hit {
		outcome = cacheHit
	}
	if measured.status != http.StatusOK && measured.status != http.StatusPartialContent && measured.status != http.StatusNotModified {
		outcome = cacheFailure
	}
	length, lengthErr := strconv.ParseInt(measured.Header().Get("Content-Length"), 10, 64)
	incomplete := lengthErr == nil && measured.status != http.StatusNotModified && measured.bytes != length
	if measured.failed || incomplete {
		reason := measured.reason
		if r.Context().Err() != nil {
			reason = deliveryFailure(r.Context().Err())
		} else if reason == "" {
			reason = "length_mismatch"
		}
		s.log.Warn("cache response incomplete", "kind", "actions_archive", "object", label, "reason", reason, "status", measured.status, "expected_bytes", length, "delivered_bytes", measured.bytes)
	}
	s.recordTransfer(l.token, false, outcome, measured.bytes, measured.failed || incomplete)
}

// finishStream accounts for a miss streamed to the guest that started its fill.
// The response is committed: a failed fill ends it early, as a failed direct
// download would.
func (s *Service) finishStream(l lease, label string, f *Object, err error, tee *streamTee, measured *transferWriter) {
	if f != nil {
		_ = f.Close()
	}
	if err != nil {
		reason, status := failureDetails(err)
		s.log.Warn("cache fill unavailable", "kind", "actions_archive", "object", label, "reason", reason, "status", status, "bytes", l.size, "delivered_bytes", measured.bytes)
	} else {
		s.log.Info("cache object served", "kind", "actions_archive", "object", label, "hit", false, "bytes", l.size)
	}
	if err == nil && (tee.clientErr != nil || measured.bytes != l.size) {
		s.log.Warn("cache response incomplete", "kind", "actions_archive", "object", label, "reason", deliveryFailure(tee.clientErr), "status", http.StatusOK, "expected_bytes", l.size, "delivered_bytes", measured.bytes)
	}
	s.recordTransfer(l.token, false, cacheMiss, measured.bytes, err != nil || tee.clientErr != nil || measured.bytes != l.size)
}

func (s *Service) objectHeaders(w http.ResponseWriter, l lease) {
	w.Header().Set("ETag", l.etag)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("x-ms-blob-type", "BlockBlob")
	w.Header().Set("x-ms-request-id", "bivouac")
	w.Header().Set("x-ms-version", "2020-04-08")
}

// upstreamRequest is a guest's authenticated submission of a signed URL.
type upstreamRequest struct {
	token  string
	grant  grant
	raw    string
	parsed *url.URL
}

// readUpstreamRequest authenticates the guest and decodes its signed URL. It
// writes the HTTP error itself when the request is unusable.
func (s *Service) readUpstreamRequest(w http.ResponseWriter, r *http.Request) (upstreamRequest, bool) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	g, ok := s.grants[token]
	s.mu.Unlock()
	if !ok || time.Now().After(g.expires) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return upstreamRequest{}, false
	}
	var body struct {
		URL string `json:"url"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return upstreamRequest{}, false
	}
	parsed, err := url.Parse(body.URL)
	if err != nil || !s.validate(parsed) {
		http.Error(w, "unsupported upstream", http.StatusBadRequest)
		return upstreamRequest{}, false
	}
	return upstreamRequest{token: token, grant: g, raw: body.URL, parsed: parsed}, true
}

// signedExpiry is the earlier of limit and the URL's SAS expiry.
func signedExpiry(u *url.URL, limit time.Time) time.Time {
	if se, err := time.Parse(time.RFC3339, u.Query().Get("se")); err == nil && se.Before(limit) {
		return se
	}
	return limit
}

// activeLeases prunes expired leases and counts the guest's remainder. Caller
// holds s.mu.
func (s *Service) activeLeases(token string) int {
	count := 0
	for id, l := range s.leases {
		if time.Now().After(l.expires) {
			delete(s.leases, id)
		} else if l.token == token {
			count++
		}
	}
	return count
}

func (s *Service) createLease(w http.ResponseWriter, r *http.Request) {
	u, ok := s.readUpstreamRequest(w, r)
	if !ok {
		return
	}
	token, g, parsed := u.token, u.grant, u.parsed
	s.mu.Lock()
	count := s.activeLeases(token)
	s.mu.Unlock()
	if count >= 64 {
		http.Error(w, "lease limit", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.raw, nil)
	if err != nil {
		http.Error(w, "invalid upstream", http.StatusBadRequest)
		return
	}
	response, err := s.client.Do(req)
	if err != nil {
		reason, _ := failureDetails(upstreamFailure(err))
		s.log.Info("cache lease unavailable", "reason", reason)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	_ = response.Body.Close()
	// HEAD validates this fresh signed capability even when bytes are cached.
	// Never authorize a read by a guessed object identity or an expired SAS.
	if response.StatusCode != 200 || response.ContentLength < 0 || response.ContentLength > s.store.maxObject {
		reason := "upstream_status"
		if response.StatusCode == http.StatusOK {
			reason = "object_limit"
		}
		s.log.Info("cache lease unavailable", "reason", reason, "status", response.StatusCode, "bytes", response.ContentLength)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	etag := response.Header.Get("ETag")
	if etag == "" {
		http.Error(w, "upstream lacks identity", http.StatusBadGateway)
		return
	}
	key := archiveKey(parsed, etag, response.ContentLength)
	id := randomToken()
	expires := time.Now().Add(5 * time.Minute)
	if g.expires.Before(expires) {
		expires = g.expires
	}
	expires = signedExpiry(parsed, expires)
	if time.Now().After(expires) {
		http.Error(w, "expired upstream", http.StatusForbidden)
		return
	}
	l := lease{token: token, upstream: u.raw, key: key, etag: etag, size: response.ContentLength, expires: expires}
	s.mu.Lock()
	// Recheck admission and revocation after the upstream round trip. Concurrent
	// lease requests cannot exceed the bound or revive a deleted guest's grant.
	_, valid := s.grants[token]
	if !valid || s.activeLeases(token) >= 64 {
		s.mu.Unlock()
		http.Error(w, "lease unavailable", http.StatusTooManyRequests)
		return
	}
	s.leases[id] = l
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		URL string `json:"url"`
	}{g.url + "/object/" + id})
}

// archiveKey names an Actions archive by blob location and upstream identity.
// It excludes the SAS query, so fresh signed URLs share one object.
func archiveKey(u *url.URL, etag string, size int64) string {
	return u.Host + u.EscapedPath() + "\x00" + etag + "\x00" + strconv.FormatInt(size, 10)
}

func (s *Service) fetch(l lease, label string, out io.Writer) error {
	req, err := http.NewRequest(http.MethodGet, l.upstream, nil)
	if err != nil {
		return errors.New("invalid upstream")
	}
	return s.download(req, label, l.etag, l.size, func(response *http.Response) error {
		if response.StatusCode != http.StatusOK {
			return &fault{reason: "upstream_status", status: response.StatusCode}
		}
		if response.Header.Get("ETag") != l.etag {
			return failure("upstream_identity")
		}
		if response.ContentLength >= 0 && response.ContentLength != l.size {
			return failure("length_mismatch")
		}
		return nil
	}, out)
}

func allowedURL(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return strings.HasSuffix(host, ".blob.core.windows.net") && u.RawQuery != ""
}

func publicClient() *http.Client { return publicClientAdmission(nil) }
func publicClientAdmission(admit func(net.IP) bool) *http.Client {
	return publicClientResolvers(admit, nil)
}
func publicClientResolvers(admit func(net.IP) bool, servers []string) *http.Client {
	resolve := macnetwork.Resolver(servers)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true // Cache objects are opaque upstream bytes.
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid upstream address")
		}
		ips, err := resolve(ctx, host)
		if err != nil {
			return nil, errors.New("upstream resolution failed")
		}
		ip, err := upstreamIP(ips, admit)
		if err != nil {
			return nil, err
		}
		conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil && admit != nil {
			return &checkedUpstream{Conn: conn, ip: ip, admit: admit}, nil
		}
		return conn, err
	}
	var roundTripper http.RoundTripper = transport
	if admit != nil {
		roundTripper = &admissionTransport{transport: transport, admit: admit}
	}
	return &http.Client{Transport: roundTripper, Timeout: 10 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("redirect limit")
		}
		h := strings.ToLower(r.URL.Hostname())
		if r.URL.Scheme != "https" || r.URL.Port() != "" || r.URL.User != nil || (h != "github.com" && h != "release-assets.githubusercontent.com" && h != "objects.githubusercontent.com" && !strings.HasSuffix(h, ".blob.core.windows.net")) {
			return errors.New("unsupported redirect")
		}
		return nil
	}}
}

func publicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	// IsGlobalUnicast includes special-purpose networks which can be routed
	// locally. A guest proxy must never become a route into the host's network.
	for _, network := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001:2::/48"} {
		if netip.MustParsePrefix(network).Contains(address) {
			return false
		}
	}
	return true
}

// Stats returns only non-sensitive storage totals, for diagnostics and tests.
func (s *Store) Stats() (int, int64, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries), s.used, s.reserved
}

// RestrictMacNetwork is called before attaching guests on a macOS host. Each upstream
// dial rejects current host addresses/prefixes and IPv6 as well as special IPs.
func (s *Service) RestrictMacNetwork(servers []string) {
	s.client.CloseIdleConnections()
	if s.macPolicy == nil {
		s.macPolicy = macnetwork.NewCache()
	}
	s.client = publicClientResolvers(s.macPolicy.Public, servers)
}

// All usable answers must be admitted before choosing one, preventing a mixed
// public/private DNS response from bypassing denial. Isolated macOS-host transports
// discard public IPv6 answers and require an admitted IPv4 alternative.
func upstreamIP(ips []net.IPAddr, admit func(net.IP) bool) (net.IP, error) {
	var selected net.IP
	for _, ip := range ips {
		if !publicIP(ip.IP) {
			return nil, errors.New("non-public upstream")
		}
		if admit != nil && ip.IP.To4() == nil {
			continue
		}
		if admit != nil && !admit(ip.IP) {
			return nil, errors.New("non-public upstream")
		}
		if selected == nil {
			selected = ip.IP
		}
	}
	if selected == nil {
		return nil, errors.New("upstream address unavailable")
	}
	return selected, nil
}

// MaxEndpointConnections is the per-VM host listener bound.
func (s *Service) MaxEndpointConnections() int {
	if s.endpointLimit == 0 {
		return 256
	}
	return s.endpointLimit
}

// SetEndpointLimit is called before attaching guests, after config validation.
func (s *Service) SetEndpointLimit(limit int) { s.endpointLimit = limit }
