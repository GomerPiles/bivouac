package cache

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// GuestProxy bridges ordinary loopback HTTP proxy clients to the authenticated
// host TLS service. Host capabilities never appear in proxy environment values.
type GuestProxy struct {
	bootstrap       Bootstrap
	endpoint        *url.URL
	tlsConfig       *tls.Config
	proxied, direct *http.Transport
}

func NewGuestProxy(b Bootstrap) (*GuestProxy, error) {
	endpoint, err := url.Parse(b.URL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Path != "" || !digestString(b.Token) {
		return nil, errors.New("invalid guest proxy configuration")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.New("load guest trust")
	}
	if !roots.AppendCertsFromPEM([]byte(b.CA)) {
		return nil, errors.New("invalid guest proxy trust")
	}
	config := &tls.Config{RootCAs: roots, ServerName: endpoint.Hostname(), MinVersion: tls.VersionTLS12}
	direct := http.DefaultTransport.(*http.Transport).Clone()
	direct.Proxy = nil
	direct.DisableCompression = true
	proxied := direct.Clone()
	proxied.Proxy = http.ProxyURL(endpoint)
	proxied.TLSClientConfig = config.Clone()
	proxied.TLSClientConfig.ServerName = "" // Destination names are checked independently.
	proxied.ProxyConnectHeader = http.Header{"Proxy-Authorization": {"Bearer " + b.Token}}
	return &GuestProxy{bootstrap: b, endpoint: endpoint, tlsConfig: config, proxied: proxied, direct: direct}, nil
}

func (p *GuestProxy) Close() { p.proxied.CloseIdleConnections(); p.direct.CloseIdleConnections() }

func (p *GuestProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	request := r.Clone(r.Context())
	request.RequestURI = ""
	cleanHeaders(request.Header)
	proxied := request
	if request.URL.Scheme == "http" {
		// A plain-http forward request reaches the host proxy as its own request
		// line, so it carries the capability. An https request is sent inside a
		// CONNECT tunnel whose origin may be opaque to the host: there the
		// capability travels only in ProxyConnectHeader, never to the origin.
		proxied = request.Clone(request.Context())
		proxied.Header.Set("Proxy-Authorization", "Bearer "+p.bootstrap.Token)
	}
	response, err := p.proxied.RoundTrip(proxied)
	if err != nil || response.StatusCode >= 500 || response.StatusCode == http.StatusProxyAuthRequired {
		// Replaying an ambiguous upload could cause side effects. Only idempotent
		// downloads fall back after a completed/attempted upstream request. The
		// direct request never carried the capability.
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if response != nil {
				_ = response.Body.Close()
			}
			response, err = p.direct.RoundTrip(request)
		}
	}
	if err != nil {
		http.Error(w, "download transport unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	cleanHeaders(response.Header)
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (p *GuestProxy) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || host == "" || port != "443" {
		http.Error(w, "unsupported destination", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	upstream, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: p.tlsConfig}).DialContext(ctx, "tcp", p.endpoint.Host)
	var buffered net.Conn
	if err == nil {
		_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
		request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: r.Host}, Host: r.Host, Header: http.Header{"Proxy-Authorization": {"Bearer " + p.bootstrap.Token}}}
		err = request.Write(upstream)
		reader := bufio.NewReader(upstream)
		var response *http.Response
		if err == nil {
			response, err = http.ReadResponse(reader, request)
		}
		if err == nil && response.StatusCode != http.StatusOK {
			err = errors.New("host proxy unavailable")
		}
		if err == nil {
			_ = upstream.SetDeadline(time.Time{})
			buffered = &readerConn{Conn: upstream, reader: reader}
		} else {
			_ = upstream.Close()
		}
	}
	if err != nil {
		// A failed CONNECT has transmitted no origin request. A direct tunnel is
		// safe for all methods and keeps upstream TLS validation in the caller.
		buffered, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(r.Context(), "tcp", r.Host)
	}
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = buffered.Close() }()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy unavailable", http.StatusBadGateway)
		return
	}
	conn, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if buffer.Flush() != nil {
		return
	}
	// Some HTTP clients send cleartext HTTP inside an HTTPS CONNECT tunnel.
	// The bridge is loopback-only: translate that protocol into HTTPS upstream
	// rather than letting it reach a server expecting a TLS ClientHello.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	first, err := buffer.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	if first[0] != 0x16 {
		_ = buffered.Close()
		listener := &oneListener{conn: &readerConn{Conn: conn, reader: buffer.Reader}, done: make(chan struct{})}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if !sameAuthority(request.Host, host) || request.URL.IsAbs() && (request.URL.Scheme != "https" || !sameAuthority(request.URL.Host, host)) {
				http.Error(w, "invalid authority", http.StatusForbidden)
				return
			}
			request.URL.Scheme = "https"
			request.URL.Host = r.Host
			p.ServeHTTP(w, request)
		}), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0)}
		_ = server.Serve(listener)
		return
	}
	relay(&readerConn{Conn: conn, reader: buffer.Reader}, buffered)
}

// RunGuestProxy is a private guest CLI; it never resolves host paths or secrets.
func RunGuestProxy(ctx context.Context, configPath, envPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return errors.New("read guest proxy configuration")
	}
	var bootstrap Bootstrap
	if json.Unmarshal(data, &bootstrap) != nil || !bootstrap.ReleaseProxy {
		return errors.New("guest release proxy is disabled")
	}
	proxy, err := NewGuestProxy(bootstrap)
	if err != nil {
		return err
	}
	defer proxy.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.New("listen for guest proxy")
	}
	defer func() { _ = listener.Close() }()
	// Only public loopback/gateway addresses go in this shell environment file.
	endpoint := "http://" + listener.Addr().String()
	if net.ParseIP(proxy.endpoint.Hostname()) == nil {
		return errors.New("invalid guest gateway")
	}
	environment := endpoint + "\n" + proxy.endpoint.Hostname() + "\n"
	if err = os.WriteFile(envPath, []byte(environment), 0o600); err != nil {
		return errors.New("publish guest proxy endpoint")
	}
	defer func() { _ = os.Remove(envPath) }()
	server := &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { <-ctx.Done(); _ = server.Close() }()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return errors.New("guest proxy stopped")
}
