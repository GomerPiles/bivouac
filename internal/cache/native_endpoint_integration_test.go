//go:build integration && darwin

package cache

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cachelink"
	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/paths"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/rootnet"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/vm"
)

type nativeCacheInput struct {
	Bootstrap Bootstrap
	Readers   int
	Raw       bool
	Duplex    bool
}
type nativeCacheResult struct {
	Readers  int
	Bytes    int64
	Seconds  float64
	Failures int
}

// Private fixture operations emit only fixed numeric JSON. Bootstrap/capabilities
// enter via stdin and never enter process arguments, logs, or durable state.
func TestNativeCacheEndpointFixture(t *testing.T) {
	if os.Args[len(os.Args)-1] != "native-cache-endpoint" {
		return
	}
	code := func() int {
		if err := RunGuestEndpoint(context.Background(), guestStdio{}); err != nil {
			class, code := guestagent.DiagnosticError(err)
			_, _ = fmt.Fprintf(os.Stderr, "fixture_stage=endpoint error_class=%s exit_code=%d\n", class, code)
			return 2
		}
		return 0
	}()
	os.Exit(code)
}
func TestNativeCacheReaderFixture(t *testing.T) {
	if os.Args[len(os.Args)-1] != "native-cache-reader" {
		return
	}
	code := func() int {
		var input nativeCacheInput
		if json.NewDecoder(io.LimitReader(os.Stdin, 64<<10)).Decode(&input) != nil || input.Readers < 1 || input.Readers > 65536 {
			return 2
		}
		if input.Duplex {
			if input.Readers > 32 {
				return 2
			}
			return nativeDuplex(input.Readers)
		}

		connectTimeout := "5"
		args := []string{"--http1.1", "--parallel", "--parallel-immediate", "--parallel-max", strconv.Itoa(input.Readers), "--silent", "--fail", "--connect-timeout", connectTimeout, "--max-time", "40", "--write-out", "%{size_download} %{http_code} %{exitcode}\n"}
		target := "http://192.0.2.1:7443/control"
		if input.Raw {
			args = append(args, "--noproxy", "*")
		} else {
			proxy, err := NewGuestProxy(input.Bootstrap)
			if err != nil {
				return 2
			}
			defer proxy.Close()
			proxy.directDial = func(context.Context, string, string) (net.Conn, error) { return nil, io.ErrClosedPipe }
			server := httptest.NewServer(proxy)
			defer server.Close()
			ca, err := os.CreateTemp("", "bivouac-cache-fixture-ca-")
			if err != nil {
				return 2
			}
			defer func() { _ = os.Remove(ca.Name()) }()
			if _, err = io.WriteString(ca, input.Bootstrap.CA); err != nil {
				_ = ca.Close()
				return 2
			}
			_ = ca.Close()
			args = append(args, "--proxy", server.URL, "--noproxy", "", "--cacert", ca.Name())
			target = "https://github.com/example/deps/releases/download/v1/control"
		}
		for range input.Readers {
			args = append(args, "--output", "/dev/null", target)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/curl", args...)
		output := &nativeMetricBuffer{limit: input.Readers * 128}
		cmd.Stdout = output
		stderr := guestagent.NewDiagnosticStderr()
		defer func() { _ = stderr.Close() }()
		cmd.Stderr = stderr
		start := time.Now()
		runErr := cmd.Run()
		if runErr != nil {
			_ = stderr.Close()
			text, truncated := stderr.Text()
			class, code := guestagent.DiagnosticError(runErr)
			_, _ = fmt.Fprintf(os.Stderr, "fixture_stage=curl error_class=%s exit_code=%d stderr_truncated=%t stderr=%q\n", class, code, truncated, text)
		}
		result := nativeCacheResult{Readers: input.Readers, Seconds: time.Since(start).Seconds()}
		lines := strings.Fields(output.String())
		if len(lines) != input.Readers*3 {
			return 3
		}
		for i := 0; i < len(lines); i += 3 {
			size, e := strconv.ParseInt(lines[i], 10, 64)
			if e != nil || size < 0 {
				return 3
			}
			result.Bytes += size
			if lines[i+1] != "200" || lines[i+2] != "0" {
				result.Failures++
			}
		}
		if runErr != nil && result.Failures == 0 {
			result.Failures++
		}
		if json.NewEncoder(os.Stdout).Encode(result) != nil {
			return 3
		}
		return 0
	}()
	os.Exit(code)
}

// Native Go sockets exercise both Ethernet directions together. One receiver
// stays unread until the other fifteen exchanges complete. Its 64 MiB exceeds
// the bounded TCP buffers, establishing a blocked receiver rather than delays.
func nativeDuplex(readers int) int {
	results := make(chan nativeCacheResult, readers)
	var wg sync.WaitGroup
	var remaining atomic.Int32
	remaining.Store(int32(readers - 1)) //nolint:gosec // Fixture input is bounded to 1..32.
	othersDone := make(chan struct{})
	if readers == 1 {
		close(othersDone)
	}
	var headersRemaining atomic.Int32
	headersRemaining.Store(int32(readers)) //nolint:gosec // Same bounded fixture input.
	headersReady := make(chan struct{})
	start := time.Now()
	for index := range readers {
		wg.Go(func() {
			result := nativeCacheResult{}
			defer func() {
				results <- result
				if index != 0 && remaining.Add(-1) == 0 {
					close(othersDone)
				}
			}()
			size := int64(4 << 20)
			if index == 0 {
				size = 64 << 20
			}
			conn, err := net.DialTimeout("tcp4", "192.0.2.1:7443", 5*time.Second)
			if err != nil {
				result.Failures = 1
				return
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			request, err := http.NewRequest(http.MethodPost, "http://192.0.2.1:7443/duplex", io.NopCloser(io.LimitReader(cacheZeroReader{}, size)))
			if err != nil {
				result.Failures = 1
				return
			}
			request.ContentLength, request.Close = size, true
			written := make(chan error, 1)
			go func() { written <- request.Write(conn) }()
			response, err := http.ReadResponse(bufio.NewReader(conn), request)
			if err == nil {
				if headersRemaining.Add(-1) == 0 {
					close(headersReady)
				}
				// All sixteen streams exist before any reader can finish. In
				// particular, the held receiver cannot arrive after its peers.
				select {
				case <-headersReady:
				case <-time.After(20 * time.Second):
					result.Failures = 1
					_ = conn.Close()
				}
				var body io.Reader = response.Body
				if index == 0 {
					select {
					case <-othersDone:
					case <-time.After(20 * time.Second):
						result.Failures = 1
						_ = conn.Close()
					}
				}
				result.Bytes, err = io.Copy(io.Discard, body)
				_ = response.Body.Close()
				if response.StatusCode != http.StatusOK || result.Bytes != size || response.Trailer.Get("Bivouac-Upload-Bytes") != strconv.FormatInt(size, 10) {
					result.Failures = 1
				}
			} else {
				_ = conn.Close()
			}
			if writeErr := <-written; err != nil || writeErr != nil {
				result.Failures = 1
			}
		})
	}
	wg.Wait()
	close(results)
	result := nativeCacheResult{Readers: readers, Seconds: time.Since(start).Seconds()}
	for r := range results {
		result.Bytes += r.Bytes
		result.Failures += r.Failures
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return 3
	}
	return 0
}

// Hold actual occupied payload sockets until the public probes acknowledge
// completion. This is a bounded test barrier, separate from production queues.
type nativeBarrierListener struct {
	net.Listener
	ctx            context.Context
	ready, release chan struct{}
	active         atomic.Int32
	once           sync.Once
}

func (l *nativeBarrierListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.active.Add(1) == 32 {
		l.once.Do(func() { close(l.ready) })
	}
	return &nativeBarrierConn{Conn: c, owner: l}, nil
}

type nativeBarrierConn struct {
	net.Conn
	owner *nativeBarrierListener
	once  sync.Once
}

func (c *nativeBarrierConn) Write(b []byte) (int, error) {
	select {
	case <-c.owner.release:
		return c.Conn.Write(b)
	default:
	}
	// The raw occupancy phase must never retain a writer indefinitely if its
	// controlling probe fails. Production deadlines are unchanged.
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-c.owner.release:
		return c.Conn.Write(b)
	case <-timer.C:
		return 0, os.ErrDeadlineExceeded
	case <-c.owner.ctx.Done():
		return 0, c.owner.ctx.Err()
	}
}
func (c *nativeBarrierConn) Close() error {
	c.once.Do(func() { c.owner.active.Add(-1) })
	return c.Conn.Close()
}

type nativeMetricBuffer struct {
	bytes.Buffer
	limit int
}

func (b *nativeMetricBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(p)
}

// Invoked by the provider lab only while it owns a recorded disposable guest.
// The local upstream bypass exists exclusively in this service fixture.
func TestNativeCacheLocalTransport(t *testing.T) {
	name := os.Getenv("BIVOUAC_NATIVE_CACHE_GUEST")
	if name == "" {
		t.Skip("native cache fixture not selected")
	}
	if os.Getenv("BIVOUAC_ROOTLESS_LAB") != "1" || os.Getenv("BIVOUAC_HOME") == "" || !strings.HasPrefix(name, "bivouac-macos-rootless-lab-") {
		t.Fatal("explicit isolated lab guest required")
	}
	cacheMax, warmReaders, err := nativeLabCacheBounds(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("BIVOUAC_LAB_BURST_PROBES") == "1" && cacheMax < 32 {
		t.Fatal("native burst fixture requires at least 32 cache connections")
	}
	layout, err := paths.Resolve()
	if err != nil {
		t.Fatal("lab layout unavailable")
	}
	records, err := state.Open(layout.State, func() string { return "" })
	if err != nil {
		t.Fatal("lab records unavailable")
	}
	record, ok := records.Get(name)
	if !ok || record.Name != name || record.Provider != "macos" {
		t.Fatal("lab guest record differs")
	}
	var metadata provider.Metadata
	data, err := os.ReadFile(filepath.Join(layout.VMs, name, "bivouac.json"))
	if err != nil || json.Unmarshal(data, &metadata) != nil || metadata.ControllerID != records.ControllerID() || metadata.InstanceID != record.ID || metadata.NetworkPolicy != rootnet.PolicyID {
		t.Fatal("lab guest ownership differs")
	}
	if vm.ProveIsolation(filepath.Join(layout.VMs, name), rootnet.PolicyID) != nil {
		t.Fatal("live lab isolation unavailable")
	}
	socket, err := vm.Store(layout.VMs).SocketPath(name)
	if err != nil {
		t.Fatal("lab socket unavailable")
	}
	dial := guestagent.DialUnix(socket)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	const helper = "/tmp/bivouac-cache-native-fixture"
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("fixture executable unavailable")
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal("fixture executable unavailable")
	}
	defer func() { _ = f.Close() }()
	if nativeLabRun(t, ctx, dial, []string{"/bin/rm", "-f", helper}, nil, io.Discard) != nil || nativeLabRun(t, ctx, dial, []string{"/usr/bin/install", "-m", "0700", "/dev/null", helper}, nil, io.Discard) != nil || nativeLabRun(t, ctx, dial, []string{"/bin/dd", "of=" + helper, "status=none"}, f, io.Discard) != nil {
		t.Fatal("fixture upload failed")
	}
	const size = 32 << 20
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"native-local-control"`)
		w.Header().Set("Content-Length", strconv.Itoa(size))
		if r.Method == http.MethodGet {
			_, _ = io.CopyN(w, cacheZeroReader{}, size)
		}
	}))
	defer backend.Close()
	service, err := Start(t.TempDir(), "127.0.0.1:0", "127.0.0.1", 256<<20, 64<<20, time.Hour, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal("fixture service failed")
	}
	defer service.Close()
	service.SetEndpointLimit(cacheMax)
	transport := backend.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
	}
	service.client = &http.Client{Transport: transport, Timeout: time.Minute}
	service.EnableReleaseProxy()

	cachePath, err := vm.Store(layout.VMs).CacheSocketPath(name)
	if err != nil {
		t.Fatal("cache socket unavailable")
	}
	rawListener, err := net.Listen("unix", cachePath)
	if err != nil {
		t.Fatal("raw fixture listener failed")
	}
	rawServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/duplex" {
			duplexSize := r.ContentLength
			if r.Method != http.MethodPost || (duplexSize != 4<<20 && duplexSize != 64<<20) || http.NewResponseController(w).EnableFullDuplex() != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			type received struct {
				count int64
				err   error
			}
			read := make(chan received, 1)
			go func() { count, err := io.CopyN(io.Discard, r.Body, duplexSize); read <- received{count, err} }()
			w.Header().Set("Trailer", "Bivouac-Upload-Bytes")
			w.WriteHeader(http.StatusOK)
			_ = http.NewResponseController(w).Flush()
			_, _ = io.CopyN(w, cacheZeroReader{}, duplexSize)
			if upload := <-read; upload.err == nil && upload.count == duplexSize {
				w.Header().Set("Bivouac-Upload-Bytes", strconv.FormatInt(upload.count, 10))
			}
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = io.CopyN(w, cacheZeroReader{}, size)
	}), ReadHeaderTimeout: time.Second, WriteTimeout: time.Minute}
	var barrier *nativeBarrierListener
	barrierDone := make(chan error, 1)
	if os.Getenv("BIVOUAC_LAB_BURST_PROBES") == "1" {
		barrier = &nativeBarrierListener{Listener: rawListener, ctx: ctx, ready: make(chan struct{}), release: make(chan struct{})}
		rawListener = barrier
		if guestagent.Run(ctx, dial, []string{"/bin/rm", "-f", "/tmp/bivouac-cache-native-stage", "/tmp/bivouac-cache-native-probe-done"}, nil, io.Discard) != nil {
			t.Fatal("native barrier reset failed")
		}
		go func() {
			defer close(barrier.release)
			select {
			case <-barrier.ready:
			case <-ctx.Done():
				barrierDone <- ctx.Err()
				return
			}
			if barrier.active.Load() != 32 || guestagent.Run(ctx, dial, []string{"/bin/dd", "of=/tmp/bivouac-cache-native-stage", "status=none"}, strings.NewReader("32-held"), io.Discard) != nil {
				barrierDone <- io.ErrUnexpectedEOF
				return
			}
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					barrierDone <- ctx.Err()
					return
				case <-ticker.C:
					if guestagent.Run(ctx, dial, []string{"/bin/test", "-e", "/tmp/bivouac-cache-native-probe-done"}, nil, io.Discard) == nil {
						if barrier.active.Load() != 32 {
							barrierDone <- io.ErrUnexpectedEOF
							return
						}
						barrierDone <- nil
						return
					}
				}
			}
		}()
	}
	go func() { _ = rawServer.Serve(rawListener) }()
	defer func() { _ = rawServer.Close(); _ = rawListener.Close() }()
	rawReaders := min(16, cacheMax)
	if barrier != nil {
		rawReaders = 32
	}
	rawInput, _ := json.Marshal(nativeCacheInput{Readers: rawReaders, Raw: true})
	rawOutput := &nativeMetricBuffer{limit: 8192}
	rawErr := nativeLabRun(t, ctx, dial, []string{helper, "-test.run=^TestNativeCacheReaderFixture$", "--", "native-cache-reader"}, bytes.NewReader(rawInput), rawOutput)
	var rawResult nativeCacheResult
	if rawErr != nil || json.Unmarshal(rawOutput.Bytes(), &rawResult) != nil {
		t.Fatal("raw native fixture failed")
	}
	t.Logf("local raw endpoint readers=%d bytes=%d seconds=%.3f mb_per_second=%.2f failures=%d", rawResult.Readers, rawResult.Bytes, rawResult.Seconds, float64(rawResult.Bytes)/rawResult.Seconds/1e6, rawResult.Failures)
	if rawResult.Failures != 0 || rawResult.Bytes != int64(rawReaders)*size {
		t.Error("raw virtual endpoint incomplete")
	}
	if barrier != nil {
		if err := <-barrierDone; err != nil {
			t.Fatal("native full-admission overlap unproven")
		}
		t.Log("32 raw cache-capability sockets remained occupied throughout public DNS/HTTPS probes")
	}
	duplexReaders := min(16, cacheMax)
	duplexInput, _ := json.Marshal(nativeCacheInput{Readers: duplexReaders, Raw: true, Duplex: true})
	duplexOutput := &nativeMetricBuffer{limit: 8192}
	duplexErr := nativeLabRun(t, ctx, dial, []string{helper, "-test.run=^TestNativeCacheReaderFixture$", "--", "native-cache-reader"}, bytes.NewReader(duplexInput), duplexOutput)
	_ = rawServer.Close()
	_ = rawListener.Close()
	var duplexResult nativeCacheResult
	parseDuplexErr := json.Unmarshal(duplexOutput.Bytes(), &duplexResult)
	t.Logf("native full-duplex held-reader: readers=%d download_bytes=%d seconds=%.3f failures=%d", duplexResult.Readers, duplexResult.Bytes, duplexResult.Seconds, duplexResult.Failures)
	if duplexErr != nil || parseDuplexErr != nil || duplexResult.Failures != 0 || duplexResult.Bytes != int64((duplexReaders-1)*4+64)<<20 {
		t.Fatal("native full-duplex/slow-reader transfer failed")
	}
	t.Logf("host acknowledged all upload bytes; peers_before_held_receiver=%d", duplexReaders-1)
	controlStderr := guestagent.NewDiagnosticStderr()
	defer func() { _ = controlStderr.Close() }()
	control, err := guestagent.DuplexWithStderr(ctx, dial, []string{helper, "-test.run=^TestNativeCacheEndpointFixture$", "--", "native-cache-endpoint"}, controlStderr)
	if err != nil {
		nativeLabFailure(t, "control", err, controlStderr)
		t.Fatal("native cache control failed")
	}
	listener, err := vm.Store(layout.VMs).ListenCache(name, cachelink.Payload)
	if err != nil {
		_ = control.Close()
		t.Fatal("native cache listener failed")
	}
	revocation, err := vm.Store(layout.VMs).ListenCache(name, cachelink.Revocation)
	if err != nil {
		_ = listener.Close()
		_ = control.Close()
		t.Fatal("native revocation listener failed")
	}

	bootstrap, err := service.AttachEndpoint(ctx, name, control, listener, revocation, GrantCapabilities{ReleaseProxy: true})
	if err != nil {
		nativeLabFailure(t, "attachment", err, controlStderr)
		t.Fatal("native cache attachment failed")
	}
	defer clear(bootstrap)
	var settings Bootstrap
	if json.Unmarshal(bootstrap, &settings) != nil {
		t.Fatal("invalid fixture bootstrap")
	}
	warm := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://github.com/example/deps/releases/download/v1/control", nil)
	request.Header.Set("Proxy-Authorization", "Bearer "+settings.Token)
	service.ServeHTTP(warm, request)
	if warm.Code != http.StatusOK || warm.Body.Len() != size {
		t.Fatal("local release prefill failed")
	}
	readerCounts := []int{32, 1, 8, 16, 32}
	if warmReaders != 0 {
		readerCounts = []int{warmReaders}
	}
	for _, readers := range readerCounts {
		readers = min(readers, cacheMax)
		beforeHits := service.Snapshot().Releases.Hits
		input, _ := json.Marshal(nativeCacheInput{Bootstrap: settings, Readers: readers})
		output := &nativeMetricBuffer{limit: readers * 128}
		err := nativeLabRun(t, ctx, dial, []string{helper, "-test.run=^TestNativeCacheReaderFixture$", "--", "native-cache-reader"}, bytes.NewReader(input), output)
		clear(input)
		if err != nil {
			t.Fatal("native fixture client failed")
		}
		var result nativeCacheResult
		if json.Unmarshal(output.Bytes(), &result) != nil || result.Readers != readers || result.Seconds <= 0 {
			t.Fatal("native metrics invalid")
		}
		t.Logf("local native endpoint readers=%d bytes=%d seconds=%.3f mb_per_second=%.2f failures=%d", readers, result.Bytes, result.Seconds, float64(result.Bytes)/result.Seconds/1e6, result.Failures)
		if result.Failures != 0 || result.Bytes != int64(readers)*size {
			t.Error("native cache transfer incomplete")
		}
		hits := service.Snapshot().Releases.Hits - beforeHits
		t.Logf("local_warm_cache readers=%d cache_hits=%d", readers, hits)
		if hits < uint64(readers) { //nolint:gosec // Lab readers are validated as positive and at most 65536.
			t.Error("local warm transfers did not produce verified cache hits")
		}
	}
}

func nativeLabCacheBounds(env func(string) string) (int, int, error) {
	c, err := config.Parse([]byte(config.Example))
	if err != nil {
		return 0, 0, err
	}
	bound, readers := c.Cache.MaxConnections, 0
	for _, field := range []struct {
		name string
		dst  *int
	}{{"BIVOUAC_LAB_CACHE_MAX_CONNECTIONS", &bound}, {"BIVOUAC_LAB_CACHE_CONCURRENCY", &readers}} {
		if value := env(field.name); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 {
				return 0, 0, errors.New("native lab cache limits require positive integers")
			}
			*field.dst = n
		}
	}
	c.Cache.MaxConnections = bound
	if err := c.Validate(); err != nil {
		return 0, 0, err
	}
	if readers > bound {
		return 0, 0, errors.New("native cache readers exceed configured endpoint bound")
	}
	return bound, readers, nil
}

func TestNativeLabCacheBoundsUnit(t *testing.T) {
	for _, test := range []struct {
		values         map[string]string
		bound, readers int
		valid          bool
	}{
		{nil, 256, 0, true},
		{map[string]string{"BIVOUAC_LAB_CACHE_CONCURRENCY": "64"}, 256, 64, true},
		{map[string]string{"BIVOUAC_LAB_CACHE_CONCURRENCY": "512", "BIVOUAC_LAB_CACHE_MAX_CONNECTIONS": "512"}, 512, 512, true},
		{map[string]string{"BIVOUAC_LAB_CACHE_CONCURRENCY": "257"}, 0, 0, false},
		{map[string]string{"BIVOUAC_LAB_CACHE_MAX_CONNECTIONS": "65537"}, 0, 0, false},
		{map[string]string{"BIVOUAC_LAB_CACHE_CONCURRENCY": "-1"}, 0, 0, false},
	} {
		bound, readers, err := nativeLabCacheBounds(func(k string) string { return test.values[k] })
		if (err == nil) != test.valid || (err == nil && (bound != test.bound || readers != test.readers)) {
			t.Fatal("native cache lab bounds differ", err)
		}
	}
}

func nativeLabFailure(t *testing.T, phase string, err error, stderr *guestagent.DiagnosticStderr) {
	t.Helper()
	_ = stderr.Close()
	text, truncated := stderr.Text()
	class, code := guestagent.DiagnosticError(err)
	t.Logf("fixture_failure phase=%s error_class=%s exit_code=%d stderr_truncated=%t stderr=%q", phase, class, code, truncated, text)
}
func nativeLabRun(t *testing.T, ctx context.Context, dial guestagent.Dialer, argv []string, input io.Reader, output io.Writer) error {
	t.Helper()
	stderr := guestagent.NewDiagnosticStderr()
	defer func() { _ = stderr.Close() }()
	err := guestagent.RunWithStderr(ctx, dial, argv, input, output, stderr)
	if err != nil {
		nativeLabFailure(t, "native_guest", err, stderr)
	}
	return err
}
