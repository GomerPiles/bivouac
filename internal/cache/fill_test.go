package cache

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// gatedObject serves one object like Azure. A full GET sends half the bytes,
// then waits for gate, aborts or goes idle; a range GET serves the rest.
type gatedObject struct {
	data   []byte
	etag   string
	mode   string // "", "abort", "idle" or "changed"
	gate   chan struct{}
	gets   atomic.Int32
	ranges atomic.Int32
}

func newGatedObject(t *testing.T, mode string) *gatedObject {
	t.Helper()
	g := &gatedObject{data: make([]byte, 256<<10), etag: `"gated"`, mode: mode, gate: make(chan struct{})}
	_, _ = rand.Read(g.data)
	return g
}

func (g *gatedObject) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	size := len(g.data)
	w.Header().Set("ETag", g.etag)
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.Itoa(size))
		return
	}
	if rng := r.Header.Get("Range"); rng != "" {
		g.ranges.Add(1)
		var from int
		if _, err := fmt.Sscanf(rng, "bytes=%d-", &from); err != nil || g.mode == "changed" || r.Header.Get("If-Match") != g.etag {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, size-1, size))
		w.Header().Set("Content-Length", strconv.Itoa(size-from))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(g.data[from:])
		return
	}
	g.gets.Add(1)
	w.Header().Set("Content-Length", strconv.Itoa(size))
	_, _ = w.Write(g.data[:size/2])
	w.(http.Flusher).Flush()
	switch g.mode {
	case "abort", "changed":
		panic(http.ErrAbortHandler)
	case "idle":
		<-r.Context().Done()
		return
	}
	select {
	case <-g.gate:
	case <-r.Context().Done():
		return
	}
	_, _ = w.Write(g.data[size/2:])
}

// releaseAfter opens gate after d unless the test opened it, and reports
// whether the timer did.
func (g *gatedObject) releaseAfter(d time.Duration) *atomic.Bool {
	var fired atomic.Bool
	time.AfterFunc(d, func() {
		fired.Store(true)
		defer func() { _ = recover() }() // The test may have closed it.
		close(g.gate)
	})
	return &fired
}

// A miss reaches the guest that started its fill as upstream bytes arrive,
// rather than after the whole object is stored.
func TestArchiveMissStreamsBeforeItsFillCompletes(t *testing.T) {
	g := newGatedObject(t, "")
	backend := httptest.NewTLSServer(g)
	defer backend.Close()
	s, b, client := testService(t, backend)
	fired := g.releaseAfter(10 * time.Second)
	r, err := client.Get(makeLease(t, b, client, backend.URL+"/archive?sig=read"))
	if err != nil || r.StatusCode != http.StatusOK {
		t.Fatal("miss not served", err)
	}
	first := make([]byte, len(g.data)/2)
	if _, err := io.ReadFull(r.Body, first); err != nil || fired.Load() || !bytes.Equal(first, g.data[:len(first)]) {
		t.Fatal("miss waited for its fill", err)
	}
	close(g.gate)
	rest, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if !bytes.Equal(append(first, rest...), g.data) {
		t.Fatal("streamed miss corrupted")
	}
	waitSummary(t, s, Summary{Archives: Counters{Misses: 1, MissBytes: uint64(len(g.data))}})
	if got := restore(t, b, client, backend.URL, "/archive"); !bytes.Equal(got, g.data) || g.gets.Load() != 1 {
		t.Fatal("streamed fill was not stored", g.gets.Load())
	}
}

// A guest that leaves mid-fill does not discard it: the fill completes and the
// next read is local.
func TestArchiveFillOutlivesTheGuestThatStartedIt(t *testing.T) {
	g := newGatedObject(t, "")
	backend := httptest.NewTLSServer(g)
	defer backend.Close()
	s, b, client := testService(t, backend)
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, makeLease(t, b, client, backend.URL+"/archive?sig=read"), nil)
	r, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(r.Body, make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = r.Body.Close()
	time.Sleep(100 * time.Millisecond)
	close(g.gate)
	deadline := time.Now().Add(5 * time.Second)
	for objects, _, _ := s.store.Stats(); objects != 1; objects, _, _ = s.store.Stats() {
		if time.Now().After(deadline) {
			t.Fatal("fill ended with its guest")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := restore(t, b, client, backend.URL, "/archive"); !bytes.Equal(got, g.data) || g.gets.Load() != 1 {
		t.Fatal("retry did not reuse the fill", g.gets.Load())
	}
}

// An upstream that fails or stalls mid-transfer is resumed from the bytes
// already received; the guest sees one complete response.
func TestArchiveFillResumesMidTransfer(t *testing.T) {
	for mode, reason := range map[string]string{"abort": "upstream_body", "idle": "upstream_idle"} {
		t.Run(mode, func(t *testing.T) {
			g := newGatedObject(t, mode)
			backend := httptest.NewTLSServer(g)
			defer backend.Close()
			s, b, client := testService(t, backend)
			s.fillIdle = 300 * time.Millisecond
			logs := &syncBuffer{}
			s.log = slog.New(slog.NewTextHandler(logs, nil))
			if got := restore(t, b, client, backend.URL, "/archive"); !bytes.Equal(got, g.data) {
				t.Fatal("resumed fill corrupted", len(got))
			}
			if g.ranges.Load() != 1 || !strings.Contains(logs.String(), `msg="cache fill resumed"`) || !strings.Contains(logs.String(), "reason="+reason) {
				t.Fatal("fill not resumed", g.ranges.Load(), logs.String())
			}
			if got := restore(t, b, client, backend.URL, "/archive"); !bytes.Equal(got, g.data) || g.gets.Load() != 1 {
				t.Fatal("resumed fill was not stored")
			}
		})
	}
}

// A resume must find the same object. Otherwise the fill fails, nothing is
// stored, and the streamed response ends early.
func TestArchiveFillRefusesAChangedResume(t *testing.T) {
	g := newGatedObject(t, "changed")
	backend := httptest.NewTLSServer(g)
	defer backend.Close()
	s, b, client := testService(t, backend)
	got := restore(t, b, client, backend.URL, "/archive")
	if len(got) >= len(g.data) || !bytes.Equal(got, g.data[:len(got)]) {
		t.Fatal("changed object completed the response", len(got))
	}
	if objects, _, reserved := s.store.Stats(); objects != 0 || reserved != 0 {
		t.Fatal("changed object stored", objects, reserved)
	}
	waitSummary(t, s, Summary{Archives: Counters{Misses: 1, MissBytes: uint64(len(got)), Failures: 1}})
}

// Release misses stream the same way through the proxy.
func TestReleaseMissStreamsBeforeItsFillCompletes(t *testing.T) {
	g := newGatedObject(t, "")
	_, client, _ := proxyFixture(t, g)
	fired := g.releaseAfter(10 * time.Second)
	source := "https://github.com/example/arbitrary/releases/download/v1/arbitrary.tar.xz"
	r, err := client.Get(source)
	if err != nil || r.StatusCode != http.StatusOK {
		t.Fatal("release miss not served", err)
	}
	first := make([]byte, len(g.data)/2)
	if _, err := io.ReadFull(r.Body, first); err != nil || fired.Load() {
		t.Fatal("release miss waited for its fill", err)
	}
	close(g.gate)
	rest, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if !bytes.Equal(append(first, rest...), g.data) {
		t.Fatal("streamed release corrupted")
	}
	r, err = client.Get(source)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if !bytes.Equal(got, g.data) || g.gets.Load() != 1 {
		t.Fatal("streamed release was not stored", g.gets.Load())
	}
}

// The upload relay forwards each body as it arrives: Azure has half of a block
// or a block list before the guest sends the rest.
func TestUploadRelayStreamsBodiesToAzure(t *testing.T) {
	arrived := make(chan struct{}, 1)
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadFull(r.Body, make([]byte, r.ContentLength/2)); err == nil {
			arrived <- struct{}{}
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("ETag", `"streamed"`)
		w.WriteHeader(http.StatusCreated)
	}))
	defer backend.Close()
	s, b, client := testService(t, backend)
	s.EnableUploadStore()
	relay := createUploadLease(t, b, client, backend.URL+"/cache/streamed?sig=upload")
	ids := make([]string, 4000)
	for i := range ids {
		ids[i] = fmt.Sprintf("%08d", i)
	}
	for _, op := range []struct {
		query string
		body  []byte
	}{{"?comp=block&blockid=AAAA", bytes.Repeat([]byte("b"), 256<<10)}, {"?comp=blocklist", blockList(ids...)}} {
		in, out := io.Pipe()
		req, _ := http.NewRequest(http.MethodPut, relay+op.query, in)
		req.ContentLength = int64(len(op.body))
		req.Header.Set("Authorization", "Bearer "+b.Token)
		done := make(chan int, 1)
		go func() {
			r, err := client.Do(req)
			if err != nil {
				done <- 0
				return
			}
			_ = r.Body.Close()
			done <- r.StatusCode
		}()
		half := len(op.body) / 2
		_, _ = out.Write(op.body[:half])
		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			t.Fatal("relay held the body before forwarding", op.query)
		}
		_, _ = out.Write(op.body[half:])
		_ = out.Close()
		if status := <-done; status != http.StatusCreated {
			t.Fatal("relayed upload failed", op.query, status)
		}
	}
}
