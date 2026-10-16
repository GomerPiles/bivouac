package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func readGuestSummary(ctx context.Context, dir string) (Summary, error) {
	f, err := os.Open(filepath.Join(dir, guestConfigFile))
	if err != nil {
		return Summary{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 32<<10+1))
	_ = f.Close()
	defer clear(data)
	var b Bootstrap
	if err != nil || len(data) > 32<<10 || json.Unmarshal(data, &b) != nil {
		return Summary{}, errors.New("invalid guest cache settings")
	}
	proxy, err := NewGuestProxy(b)
	if err != nil {
		return Summary{}, errors.New("guest cache settings unavailable")
	}
	defer proxy.Close()
	// Windows-hosted guests use SSH loopback; macOS guests reach the configured
	// host address directly. Both use a literal IP, bootstrap TLS trust and the grant.
	address := net.ParseIP(proxy.endpoint.Hostname())
	if address == nil || address.IsUnspecified() || address.IsMulticast() {
		return Summary{}, errors.New("guest cache endpoint must use a literal IP")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: proxy.tlsConfig, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.URL+"/metrics", nil)
	if err != nil {
		return Summary{}, errors.New("guest cache summary unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+b.Token)
	response, err := client.Do(req) // #nosec G704 -- Fixed authenticated metrics path on the bootstrap's literal-IP TLS endpoint; redirects are refused.
	if err != nil {
		return Summary{}, errors.New("guest cache summary unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	var summary Summary
	data, err = io.ReadAll(io.LimitReader(response.Body, 4097))
	defer clear(data)
	if response.StatusCode != http.StatusOK || err != nil || len(data) > 4096 || json.Unmarshal(data, &summary) != nil {
		return Summary{}, errors.New("guest cache summary unavailable")
	}
	return summary, nil
}

// PrintGuestSummary adds one best-effort numeric line through the existing
// authenticated cache endpoint. Missing cache setup emits no extra log line.
func PrintGuestSummary(parent context.Context, out io.Writer, dir string) {
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	summary, err := readGuestSummary(ctx, dir)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		_, _ = fmt.Fprintln(out, "[bivouac cache] summary unavailable")
		return
	}
	a, r := summary.Archives, summary.Releases
	_, _ = fmt.Fprintf(out, "[bivouac cache] archives: hits=%d (%d bytes) misses=%d (%d bytes) bypasses=%d (%d bytes) failures=%d; release proxy: hits=%d (%d bytes) misses=%d (%d bytes) bypasses=%d (%d bytes) failures=%d\n", a.Hits, a.HitBytes, a.Misses, a.MissBytes, a.Bypasses, a.BypassBytes, a.Failures, r.Hits, r.HitBytes, r.Misses, r.MissBytes, r.Bypasses, r.BypassBytes, r.Failures)
}
