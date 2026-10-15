package cache

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Counters counts resolved GET requests and actual response-body bytes written
// to clients, including partial transfers. HEAD, service metadata and opaque
// tunnels are excluded. Bypasses and transfer failures have separate counts.
type Counters struct {
	Hits        uint64 `json:"hits"`
	HitBytes    uint64 `json:"hit_bytes"`
	Misses      uint64 `json:"misses"`
	MissBytes   uint64 `json:"miss_bytes"`
	Bypasses    uint64 `json:"bypasses"`
	BypassBytes uint64 `json:"bypass_bytes"`
	Failures    uint64 `json:"failures"`
}

type Summary struct {
	Archives Counters `json:"archives"`
	Releases Counters `json:"release_proxy"`
}

type cacheOutcome int

const (
	cacheHit cacheOutcome = iota
	cacheMiss
	cacheBypass
	cacheFailure
)

func (c *Counters) add(outcome cacheOutcome, bytes int64, failed bool) {
	n := uint64(max(bytes, 0))
	switch outcome {
	case cacheHit:
		c.Hits++
		c.HitBytes += n
	case cacheMiss:
		c.Misses++
		c.MissBytes += n
	case cacheBypass:
		c.Bypasses++
		c.BypassBytes += n
	}
	if failed || outcome == cacheFailure {
		c.Failures++
	}
}

func (s *Summary) add(release bool, outcome cacheOutcome, n int64, failed bool) {
	if release {
		s.Releases.add(outcome, n, failed)
	} else {
		s.Archives.add(outcome, n, failed)
	}
}

func (s *Service) recordTransfer(token string, release bool, outcome cacheOutcome, n int64, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.summary.add(release, outcome, n, failed)
	if g, ok := s.grants[token]; ok {
		g.summary.add(release, outcome, n, failed)
		s.grants[token] = g
	}
}

// Snapshot returns numeric session totals, never cache keys or capabilities.
func (s *Service) Snapshot() Summary { s.mu.Lock(); defer s.mu.Unlock(); return s.summary }

func logCounters(log *slog.Logger, scope, kind string, c Counters) {
	log.Info("cache summary", "scope", scope, "kind", kind, "hits", c.Hits, "hit_bytes", c.HitBytes, "misses", c.Misses, "miss_bytes", c.MissBytes, "bypasses", c.Bypasses, "bypass_bytes", c.BypassBytes, "transfer_failures", c.Failures)
}

// LogSummary uses the existing redacted controller sink and bounded fixed kinds.
func (s *Service) LogSummary() {
	snapshot := s.Snapshot()
	logCounters(s.log, "controller_session", "archives", snapshot.Archives)
	logCounters(s.log, "controller_session", "release_proxy", snapshot.Releases)
}

func (s *Service) serveMetrics(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	g, ok := s.grants[token]
	s.mu.Unlock()
	if !ok || time.Now().After(g.expires) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(g.summary)
}

// transferWriter preserves response headers/status while measuring only body
// bytes accepted by the underlying writer; ServeContent still owns range logic.
type transferWriter struct {
	http.ResponseWriter
	bytes  int64
	failed bool
	status int
}

func (w *transferWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *transferWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	w.bytes += int64(n)
	w.failed = w.failed || err != nil || n != len(data)
	return n, err
}

func (w *transferWriter) ReadFrom(input io.Reader) (int64, error) {
	// Preserve the underlying response writer's optimized copy path.
	n, err := io.Copy(w.ResponseWriter, input)
	w.bytes += n
	w.failed = w.failed || err != nil
	return n, err
}
