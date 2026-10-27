package vz

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/cachelink"
	"github.com/GomerPiles/bivouac/internal/linuxguest"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/vm"
)

type linuxCacheRuntime struct {
	Runtime
	guestDir                                                     string
	bootstrap                                                    cache.Bootstrap
	payload, revocation                                          net.Listener
	controlClosed, endpointDone                                  chan struct{}
	setupFailure, cleanupFailure, endpointFailure, deleteFailure bool
	cleaned, revokedBeforeCleanup                                bool
	environment                                                  []string
}

func (r *linuxCacheRuntime) ProveIsolation(name, policy string) error {
	return r.Runtime.(interface{ ProveIsolation(string, string) error }).ProveIsolation(name, policy)
}
func (r *linuxCacheRuntime) Duplex(ctx context.Context, name string, argv []string) (net.Conn, error) {
	if strings.Join(argv, " ") != linuxguest.RuntimeHelper+" cache endpoint" {
		return nil, errors.New("wrong Linux endpoint helper")
	}
	if r.endpointFailure {
		return nil, errors.New("synthetic endpoint outage")
	}
	host, guest := net.Pipe()
	r.controlClosed, r.endpointDone = make(chan struct{}), make(chan struct{})
	go func() { defer close(r.endpointDone); _ = cache.RunGuestEndpoint(ctx, guest) }()
	return &closeNotice{Conn: host, closed: r.controlClosed}, nil
}

type closeNotice struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closeNotice) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (r *linuxCacheRuntime) CacheListeners(name string) (net.Listener, net.Listener, error) {
	var err error
	r.payload, r.revocation, err = r.Runtime.CacheListeners(name)
	return r.payload, r.revocation, err
}
func (r *linuxCacheRuntime) Delete(ctx context.Context, name string) error {
	if r.deleteFailure {
		return errors.New("synthetic uncertain deletion")
	}
	return r.Runtime.Delete(ctx, name)
}
func (r *linuxCacheRuntime) Exec(ctx context.Context, name string, args []string, input io.Reader, out io.Writer) error {
	if len(args) == 4 && args[0] == linuxguest.RuntimeHelper && args[1] == "guest" && args[2] == "linux" {
		switch args[3] {
		case "cache-setup":
			data, err := io.ReadAll(input)
			if err != nil {
				return err
			}
			defer clear(data)
			if err := json.Unmarshal(data, &r.bootstrap); err != nil {
				return err
			}
			if err := r.Runtime.Exec(ctx, name, args, bytes.NewReader(data), out); err != nil {
				return err
			}
			if !r.bootstrap.ReleaseProxy {
				// Exercise real shared guest files/environment, without host trust changes.
				if err := cache.PrepareGuest(ctx, r.guestDir, data); err != nil {
					return err
				}
				environment, closeGuest, err := cache.GuestEnvironment(r.guestDir)
				if err != nil {
					return err
				}
				closeGuest()
				r.environment = environment
			}
			if r.setupFailure {
				return errors.New("synthetic partial adapter failure")
			}
			return nil
		case "cache-remove":
			if r.controlClosed != nil {
				select {
				case <-r.controlClosed:
					r.revokedBeforeCleanup = true
				default:
					return errors.New("cleanup before revocation")
				}
			}
			if err := r.Runtime.Exec(ctx, name, args, input, out); err != nil {
				return err
			}
			if r.cleanupFailure {
				return errors.New("synthetic unconfirmed cleanup")
			}
			if err := cache.RemoveGuest(r.guestDir); err != nil {
				return err
			}
			r.cleaned = true
			return nil
		}
	}
	return r.Runtime.Exec(ctx, name, args, input, out)
}

func linuxCacheFixture(t *testing.T, sudo bool) (*Provider, *linuxRecorder, *linuxCacheRuntime, provider.Spec) {
	t.Helper()
	p, guest, spec := linuxProvider(t)
	bootLinuxFixture(t, p, spec)
	m, err := vm.ReadManifest(p.vmDir(spec.Name))
	if err != nil {
		t.Fatal(err)
	}
	m.Guest.Sudo = sudo
	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(p.vmDir(spec.Name), vm.ManifestFile), data, 0600); err != nil {
		t.Fatal(err)
	}
	runtime := &linuxCacheRuntime{Runtime: p.rt, guestDir: t.TempDir()}
	p.rt = runtime
	enableFixtureCache(t, p)
	if err := p.WaitReady(context.Background(), spec.Name); err != nil {
		t.Fatal(err)
	}
	return p, guest, runtime, spec
}

func cacheEndpointClient(t *testing.T, r *linuxCacheRuntime) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(r.bootstrap.CA)) {
		t.Fatal("missing endpoint CA")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == cachelink.RevocationEndpoint {
			addr = r.revocation.Addr().String()
		} else {
			addr = r.payload.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp4", addr)
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 2 * time.Second}
}
func endpointMetrics(t *testing.T, r *linuxCacheRuntime, client *http.Client) int {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, r.bootstrap.URL+"/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+r.bootstrap.Token)
	response, err := client.Do(request)
	if err != nil {
		return 0
	}
	defer func() { _ = response.Body.Close() }()
	return response.StatusCode
}

func TestLinuxCacheAttachesBeforeJITWithOptionalSudo(t *testing.T) {
	for _, sudo := range []bool{false, true} {
		t.Run(map[bool]string{false: "without-sudo", true: "with-sudo"}[sudo], func(t *testing.T) {
			p, guest, runtime, spec := linuxCacheFixture(t, sudo)
			// The selected host helper and baseline are admission inputs only.
			// Cache startup reuses the prepared helper already inside this clone.
			if err := os.Remove(p.runner.Helper); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(p.vmDir(spec.Baseline)); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			p.log = slog.New(slog.NewJSONHandler(&logs, nil))
			if err := p.StartRunner(context.Background(), spec.Name, []byte("synthetic-private-jit")); err != nil {
				t.Fatal(err)
			}
			if runtime.bootstrap.ReleaseProxy != sudo || runtime.bootstrap.RevocationURL != cachelink.RevocationURL {
				t.Fatal("sudo gate or fixed CRL endpoint changed")
			}
			setup, seed := -1, -1
			for index, call := range guest.calls {
				text := strings.Join(call, " ")
				if strings.HasSuffix(text, "guest linux cache-setup") {
					setup = index
				}
				if strings.HasSuffix(text, "guest linux seed-jit") {
					seed = index
				}
				if strings.Contains(text, "dd of=") || strings.Contains(text, runtime.bootstrap.Token) || strings.Contains(text, "synthetic-private-jit") {
					t.Fatal("second upload or private argv")
				}
			}
			if setup < 0 || seed <= setup {
				t.Fatal("cache did not attach before JIT")
			}
			if strings.Contains(logs.String(), runtime.bootstrap.Token) || strings.Contains(logs.String(), "CERTIFICATE") || strings.Contains(logs.String(), "synthetic-private-jit") {
				t.Fatal("private cache/JIT data logged")
			}
			if !sudo && (len(runtime.environment) != 2 || !strings.HasPrefix(runtime.environment[1], "NODE_OPTIONS=")) {
				t.Fatal("ordinary caching unavailable without sudo")
			}
			client := cacheEndpointClient(t, runtime)
			if endpointMetrics(t, runtime, client) != http.StatusOK {
				t.Fatal("endpoint grant did not authenticate")
			}
			request, _ := http.NewRequest(http.MethodGet, cachelink.RevocationURL, nil)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("fixed CRL capability unavailable")
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatal("CRL endpoint rejected")
			}
			p.cache.Revoke(spec.Name)
			if endpointMetrics(t, runtime, client) == http.StatusOK {
				t.Fatal("revoked grant retained")
			}
			select {
			case <-runtime.endpointDone:
			case <-time.After(2 * time.Second):
				t.Fatal("guest endpoint survived revocation")
			}
		})
	}
}

func TestLinuxCacheFallbackRequiresRevocationAndConfirmedRemoval(t *testing.T) {
	for _, kind := range []string{"partial", "cleanup-uncertain", "endpoint-outage"} {
		t.Run(kind, func(t *testing.T) {
			p, guest, runtime, spec := linuxCacheFixture(t, false)
			runtime.setupFailure = kind != "endpoint-outage"
			runtime.cleanupFailure = kind == "cleanup-uncertain"
			runtime.endpointFailure = kind == "endpoint-outage"
			err := p.StartRunner(context.Background(), spec.Name, []byte("synthetic-jit"))
			if (err != nil) != runtime.cleanupFailure {
				t.Fatal("fallback/cleanup result differs", err)
			}
			if kind != "endpoint-outage" && !runtime.revokedBeforeCleanup {
				t.Fatal("cleanup preceded synchronous revocation")
			}
			sentJIT := false
			for _, call := range guest.calls {
				sentJIT = sentJIT || strings.HasSuffix(strings.Join(call, " "), "guest linux seed-jit")
			}
			if sentJIT == runtime.cleanupFailure {
				t.Fatal("JIT delivery ignored cleanup confirmation")
			}
			if !runtime.cleanupFailure {
				environment, closeGuest, err := cache.GuestEnvironment(runtime.guestDir)
				if err != nil || len(environment) != 0 || !runtime.cleaned {
					t.Fatal("fallback retained private adapter", err)
				}
				closeGuest()
			}
		})
	}
}

func TestLinuxCacheRevokesOnlyAfterDeletionOrAbsence(t *testing.T) {
	for _, kind := range []string{"delete", "absent", "shutdown"} {
		t.Run(kind, func(t *testing.T) {
			p, guest, runtime, spec := linuxCacheFixture(t, false)
			if err := p.StartRunner(context.Background(), spec.Name, []byte("synthetic-jit")); err != nil {
				t.Fatal(err)
			}
			client := cacheEndpointClient(t, runtime)
			if endpointMetrics(t, runtime, client) != http.StatusOK {
				t.Fatal("initial grant unavailable")
			}
			switch kind {
			case "delete":
				if err := p.Stop(context.Background(), spec.Name, time.Second); err != nil {
					t.Fatal(err)
				}
				runtime.deleteFailure = true
				if err := p.Delete(context.Background(), spec.Name); err == nil {
					t.Fatal("uncertain deletion accepted")
				}
				if endpointMetrics(t, runtime, client) != http.StatusOK {
					t.Fatal("uncertain deletion revoked live guest")
				}
				runtime.deleteFailure = false
				if err := p.Delete(context.Background(), spec.Name); err != nil {
					t.Fatal(err)
				}
			case "absent":
				delete(guest.vms, spec.Name)
				if err := p.Delete(context.Background(), spec.Name); !errors.Is(err, provider.ErrNotFound) {
					t.Fatal(err)
				}
			case "shutdown":
				p.cache.Close()
			}
			if endpointMetrics(t, runtime, client) == http.StatusOK {
				t.Fatal("deleted guest/service retained a grant")
			}
			select {
			case <-runtime.endpointDone:
			case <-time.After(2 * time.Second):
				t.Fatal("endpoint lifetime leaked")
			}
		})
	}
}

// A ready clone can lose its live isolation proof before cache/JIT admission.
func TestLinuxCacheRefusesLostIsolationBeforeCredentials(t *testing.T) {
	p, guest, runtime, spec := linuxCacheFixture(t, false)
	runtime.Runtime = &linuxProof{Runtime: runtime.Runtime, refused: true}
	before := len(guest.calls)
	if err := p.StartRunner(context.Background(), spec.Name, []byte("synthetic-jit")); err == nil {
		t.Fatal("cache/JIT accepted lost isolation")
	}
	if runtime.controlClosed != nil || runtime.bootstrap.Token != "" {
		t.Fatal("unproven guest received endpoint or credentials")
	}
	for _, call := range guest.calls[before:] {
		if len(call) > 2 && call[0] == "Exec" && call[2] != "true" {
			t.Fatal("unproven guest received command")
		}
	}
}
