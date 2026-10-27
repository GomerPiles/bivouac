package cache

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPooledCachePeerIsRevalidatedWithoutLosingReuse(t *testing.T) {
	var served, dialed atomic.Int32
	var allowed atomic.Bool
	allowed.Store(true)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served.Add(1); _, _ = io.WriteString(w, "ok") }))
	defer backend.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	client := &http.Client{Transport: &admissionTransport{transport: transport, admit: func(net.IP) bool { return allowed.Load() }}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	for range 2 {
		r, err := client.Get(backend.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
	if dialed.Load() != 1 {
		t.Fatal("cache upstream connection was not reused")
	}
	allowed.Store(false)
	r, err := client.Get(backend.URL)
	if err == nil {
		_ = r.Body.Close()
		t.Fatal("new request reused a prohibited peer")
	}
	if served.Load() != 2 {
		t.Fatal("prohibited pooled request reached the peer")
	}
}
