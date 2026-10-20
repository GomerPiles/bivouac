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
	"sync"
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

type fillTransport func(*http.Request) (*http.Response, error)

func (f fillTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type immediateBody struct {
	ctx  context.Context
	left int
}

func (b *immediateBody) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if b.left == 0 {
		return 0, io.EOF
	}
	p[0] = 'x'
	b.left--
	return 1, nil
}
func (b *immediateBody) Close() error { return nil }

type slowFillWriter struct{ data bytes.Buffer }

func (w *slowFillWriter) Write(p []byte) (int, error) {
	time.Sleep(60 * time.Millisecond)
	return w.data.Write(p)
}

func TestFillIdleExcludesDestinationWrites(t *testing.T) {
	var attempts atomic.Int32
	s := &Service{work: context.Background(), fillIdle: 20 * time.Millisecond, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.client = &http.Client{Transport: fillTransport(func(r *http.Request) (*http.Response, error) {
		attempts.Add(1)
		offset := 0
		if value := r.Header.Get("Range"); value != "" {
			_, _ = fmt.Sscanf(value, "bytes=%d-", &offset)
		}
		h := http.Header{"Etag": {`"id"`}}
		status := http.StatusOK
		if offset > 0 {
			status = http.StatusPartialContent
			h.Set("Content-Range", fmt.Sprintf("bytes %d-9/10", offset))
		}
		return &http.Response{StatusCode: status, Header: h, Body: &immediateBody{ctx: r.Context(), left: 10 - offset}, Request: r}, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "https://example.invalid/object", nil)
	out := &slowFillWriter{}
	err := s.download(req, "object", `"id"`, 10, func(*http.Response) error { return nil }, out)
	if err != nil || out.data.String() != strings.Repeat("x", 10) || attempts.Load() != 1 {
		t.Fatalf("healthy upstream with slow writer: attempts=%d bytes=%d error=%v", attempts.Load(), out.data.Len(), err)
	}
}

// Both callers must keep the final byte private until length and HTTP framing
// have been checked, even when all declared bytes arrived in an earlier read.
func TestStreamWaitsForVerifiedEOF(t *testing.T) {
	for _, release := range []bool{false, true} {
		for _, mode := range []string{"valid", "overlong", "short", "framing"} {
			t.Run(fmt.Sprintf("release=%t/%s", release, mode), func(t *testing.T) {
				const size = 65536
				prefix := make(chan struct{})
				gate := make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(gate) }) }
				defer unblock()
				var gets atomic.Int32
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("ETag", `"id"`)
					if r.Method == http.MethodHead {
						w.Header().Set("Content-Length", strconv.Itoa(size))
						return
					}
					gets.Add(1)
					if r.Header.Get("Range") != "" {
						w.WriteHeader(http.StatusPreconditionFailed)
						return
					}
					// Release admission requires the GET's declared Content-Length. A test
					// transport below supplies it while preserving the real chunked body.
					n := size
					if mode == "short" {
						n--
					}
					_, _ = w.Write(bytes.Repeat([]byte("x"), n))
					w.(http.Flusher).Flush()
					close(prefix)
					<-gate
					switch mode {
					case "overlong":
						_, _ = w.Write([]byte("extra"))
					case "framing":
						panic(http.ErrAbortHandler)
					}
				})
				var s *Service
				var client *http.Client
				var source string
				if release {
					s, client, _ = proxyFixture(t, handler)
					source = "https://github.com/example/arbitrary/releases/download/v1/arbitrary.tar.xz"
					real := s.client.Transport
					s.client.Transport = fillTransport(func(r *http.Request) (*http.Response, error) {
						response, err := real.RoundTrip(r)
						if err == nil && r.Method == http.MethodGet {
							response.ContentLength = size
						}
						return response, err
					})
				} else {
					backend := httptest.NewTLSServer(handler)
					defer backend.Close()
					var b Bootstrap
					s, b, client = testService(t, backend)
					source = makeLease(t, b, client, backend.URL+"/object?sig=fixture")
				}
				type result struct {
					data   []byte
					err    error
					status int
				}
				done := make(chan result, 1)
				go func() {
					r, err := client.Get(source)
					if err != nil {
						done <- result{err: err}
						return
					}
					data, err := io.ReadAll(r.Body)
					_ = r.Body.Close()
					done <- result{data: data, err: err, status: r.StatusCode}
				}()
				<-prefix
				select {
				case got := <-done:
					unblock()
					t.Fatalf("guest completed before upstream EOF: status=%d bytes=%d error=%v", got.status, len(got.data), got.err)
				case <-time.After(100 * time.Millisecond):
				}
				unblock()
				var got result
				select {
				case got = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("stream did not finish")
				}
				if mode == "valid" {
					if got.err != nil || len(got.data) != size {
						t.Fatalf("valid stream: bytes=%d error=%v", len(got.data), got.err)
					}
				} else {
					if got.status != http.StatusOK || got.err == nil || len(got.data) >= size {
						t.Fatalf("invalid stream completed: status=%d bytes=%d error=%v", got.status, len(got.data), got.err)
					}
					if mode == "overlong" && gets.Load() != 1 {
						t.Fatalf("overlong body resumed: gets=%d", gets.Load())
					}
				}
				deadline := time.Now().Add(5 * time.Second)
				for {
					objects, _, reserved := s.store.Stats()
					if reserved == 0 && (mode != "valid" || objects == 1) {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("fill cleanup pending: objects=%d reserved=%d", objects, reserved)
					}
					time.Sleep(time.Millisecond)
				}
				objects, _, reserved := s.store.Stats()
				if reserved != 0 || (mode != "valid" && objects != 0) {
					t.Fatalf("invalid fill retained: objects=%d reserved=%d", objects, reserved)
				}
			})
		}
	}
}

func TestStreamFlushesSmallProgress(t *testing.T) {
	for _, release := range []bool{false, true} {
		t.Run(fmt.Sprintf("release=%t", release), func(t *testing.T) {
			gate := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(gate) }) }
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"id"`)
				w.Header().Set("Content-Length", "2048")
				if r.Method == http.MethodHead {
					return
				}
				_, _ = w.Write(bytes.Repeat([]byte("a"), 1024))
				w.(http.Flusher).Flush()
				<-gate
				_, _ = w.Write(bytes.Repeat([]byte("b"), 1024))
			})
			var client *http.Client
			var source string
			if release {
				_, client, _ = proxyFixture(t, handler)
				source = "https://github.com/example/arbitrary/releases/download/v1/arbitrary.tar.xz"
			} else {
				backend := httptest.NewTLSServer(handler)
				defer backend.Close()
				_, b, c := testService(t, backend)
				client = c
				source = makeLease(t, b, c, backend.URL+"/object?sig=fixture")
			}
			defer unblock()
			done := make(chan error, 1)
			go func() {
				r, err := client.Get(source)
				if err == nil {
					_, err = io.ReadFull(r.Body, make([]byte, 1023))
					_ = r.Body.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("small upstream progress was not flushed")
			}
		})
	}
}

type failingFlushWriter struct {
	*httptest.ResponseRecorder
	flushes int
}

func (w *failingFlushWriter) FlushError() error {
	w.flushes++
	return io.ErrClosedPipe
}

func TestStreamFlushFailureKeepsFill(t *testing.T) {
	for _, release := range []bool{false, true} {
		t.Run(fmt.Sprintf("release=%t", release), func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"id"`)
				w.Header().Set("Content-Length", "65536")
				if r.Method != http.MethodHead {
					_, _ = w.Write(bytes.Repeat([]byte("x"), 65536))
				}
			})
			w := &failingFlushWriter{ResponseRecorder: httptest.NewRecorder()}
			var s *Service
			if release {
				var b Bootstrap
				s, _, b = proxyFixture(t, handler)
				req, _ := http.NewRequest(http.MethodGet, "https://github.com/example/arbitrary/releases/download/v1/arbitrary.tar.xz", nil)
				if !s.cacheRelease(w, req, b.Token) {
					t.Fatal("release not cached")
				}
			} else {
				backend := httptest.NewTLSServer(handler)
				defer backend.Close()
				var b Bootstrap
				var client *http.Client
				s, b, client = testService(t, backend)
				local := makeLease(t, b, client, backend.URL+"/object?sig=fixture")
				s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, local, nil))
			}
			summary := s.Snapshot()
			counters := summary.Archives
			if release {
				counters = summary.Releases
			}
			if w.flushes != 1 || counters.Failures != 1 || w.Body.Len() >= 65536 {
				t.Fatalf("flush failure not treated as a guest write failure: flushes=%d bytes=%d counters=%+v", w.flushes, w.Body.Len(), counters)
			}
			objects, _, reserved := s.store.Stats()
			if objects != 1 || reserved != 0 {
				t.Fatalf("guest flush failure stopped fill: objects=%d reserved=%d", objects, reserved)
			}
		})
	}
}
