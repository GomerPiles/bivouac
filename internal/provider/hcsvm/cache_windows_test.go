//go:build windows

package hcsvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/engine"
	"github.com/GomerPiles/bivouac/internal/vmhost"
)

// cacheAgentFixture supplies the real port prelude and relay protocol over a pipe.
func cacheAgentFixture(t *testing.T) (net.Conn, <-chan struct{}) {
	t.Helper()
	host, guest := net.Pipe()
	closed := make(chan struct{})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close(); _ = guest.Close(); _ = listener.Close() })
	go func() {
		defer close(closed)
		defer func() { _ = guest.Close() }()
		if json.NewEncoder(guest).Encode(struct {
			Port int `json:"port"`
		}{listener.Addr().(*net.TCPAddr).Port}) != nil {
			return
		}
		_ = engine.Listen(t.Context(), guest, listener, 64)
	}()
	return host, closed
}
func enableCache(t *testing.T, p *Provider) *cache.Service {
	t.Helper()
	service, err := cache.Start(t.TempDir(), "127.0.0.1:0", "127.0.0.1", 1<<20, 1<<19, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	t.Cleanup(p.Close)
	p.SetCache(service)
	return service
}

func TestCachePartialSetupCleanupBeforeJIT(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "fallback", true: "refuse"}[cleanupFails], func(t *testing.T) {
			p, _, f := fixture(t, true)
			enableCache(t, p)
			if err := p.Create(t.Context(), spec()); err != nil {
				t.Fatal(err)
			}
			if err := p.WaitReady(t.Context(), spec().Name); err != nil {
				t.Fatal(err)
			}
			client, closed := cacheAgentFixture(t)
			f.duplex = func(context.Context) (net.Conn, error) { return client, nil }
			var bootstrap []byte
			f.runHook = func(command string, stdin []byte) error {
				if strings.HasSuffix(command, "cache-setup") {
					var b cache.Bootstrap
					if json.Unmarshal(stdin, &b) != nil || b.Token == "" || !strings.HasPrefix(b.URL, "https://127.0.0.1:") {
						t.Fatal("bootstrap not delivered over stdin")
					}
					bootstrap = stdin // Borrow only, to verify clearing after use.
					return errors.New("partial guest setup failed")
				}
				if strings.HasSuffix(command, "cache-remove") && cleanupFails {
					return errors.New("guest cleanup unavailable")
				}
				return nil
			}
			f.calls = nil
			err := p.StartRunner(t.Context(), spec().Name, []byte("opaque-test-input"))
			if (err != nil) != cleanupFails {
				t.Fatal("incorrect cleanup admission result", err)
			}
			want := []string{guestHelper + " guest windows cache-setup", guestHelper + " guest windows cache-remove"}
			if !cleanupFails {
				want = append(want, guestHelper+" guest windows seed-jit", guestHelper+" guest windows start")
			}
			var commands []string
			for _, call := range f.calls {
				commands = append(commands, call.command)
			}
			if !slices.Equal(commands, want) {
				t.Fatal("incorrect cache cleanup/JIT order")
			}
			if len(bootstrap) == 0 || !bytes.Equal(bootstrap, make([]byte, len(bootstrap))) {
				t.Fatal("bootstrap was not cleared")
			}
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("failed setup retained cache transport")
			}
		})
	}
}

func TestCacheClientOutageRemovesSettingsBeforeFallback(t *testing.T) {
	p, _, f := fixture(t, true)
	enableCache(t, p)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	if err := p.StartRunner(t.Context(), spec().Name, []byte("opaque-test-input")); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 3 || f.calls[0].command != guestHelper+" guest windows cache-remove" || f.calls[1].command != guestHelper+" guest windows seed-jit" {
		t.Fatal("attachment failure did not remove settings before JIT")
	}
}

func TestCacheRevokedOnlyAfterConfirmedDeletionOrClose(t *testing.T) {
	for _, mode := range []string{"destroyed", "absent", "destroy-not-found", "close"} {
		t.Run(mode, func(t *testing.T) {
			p, h, f := fixture(t, true)
			enableCache(t, p)
			if err := p.Create(t.Context(), spec()); err != nil {
				t.Fatal(err)
			}
			client, closed := cacheAgentFixture(t)
			f.duplex = func(context.Context) (net.Conn, error) { return client, nil }
			if err := p.StartRunner(t.Context(), spec().Name, []byte("opaque-test-input")); err != nil {
				t.Fatal(err)
			}
			h.destroyErr = errors.New("destroy uncertain")
			if err := p.Delete(t.Context(), spec().Name); err == nil {
				t.Fatal("uncertain deletion accepted")
			}
			if _, attached := p.cacheGuests[spec().Name]; !attached {
				t.Fatal("uncertain deletion revoked attachment")
			}
			select {
			case <-closed:
				t.Fatal("cache closed before confirmed deletion")
			default:
			}
			h.destroyErr = nil
			switch mode {
			case "absent":
				delete(h.guests, spec().Name)
			case "destroy-not-found":
				h.destroyErr = &vmhost.Error{Code: vmhost.CodeNotFound}
			case "close":
				p.Close()
			}
			if mode != "close" {
				if err := p.Delete(t.Context(), spec().Name); err != nil {
					t.Fatal(err)
				}
			}
			if len(p.cacheGuests) != 0 {
				t.Fatal("confirmed absence/shutdown retained attachment")
			}
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("cache client survived revocation")
			}
			p.Close() // Repeated cleanup is harmless and cannot reclaim another client.
		})
	}
}

func TestCacheAdmissionUsesCurrentGuestProof(t *testing.T) {
	for _, mode := range []string{"stopped", "foreign", "absent"} {
		t.Run(mode, func(t *testing.T) {
			p, h, f := fixture(t, true)
			enableCache(t, p)
			if err := p.Create(t.Context(), spec()); err != nil {
				t.Fatal(err)
			}
			g := h.guests[spec().Name]
			switch mode {
			case "stopped":
				g.State = vmhost.StateStopped
				h.guests[g.Name] = g
			case "foreign":
				g.Labels["controller_id"] = "other"
			case "absent":
				delete(h.guests, spec().Name)
			}
			f.duplex = func(context.Context) (net.Conn, error) {
				t.Fatal("cache opened without current guest proof")
				return nil, nil
			}
			if err := p.StartRunner(t.Context(), spec().Name, []byte("opaque-test-input")); err == nil || len(f.calls) != 0 {
				t.Fatal("unavailable or foreign guest admitted cache/JIT")
			}
		})
	}
}

func TestNoCacheSetupWithoutSetCache(t *testing.T) {
	p, _, f := fixture(t, true)
	f.duplex = func(context.Context) (net.Conn, error) {
		t.Fatal("cache client opened without SetCache")
		return nil, nil
	}
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	if err := p.StartRunner(t.Context(), spec().Name, []byte("opaque-test-input")); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || f.calls[0].command != guestHelper+" guest windows seed-jit" {
		t.Fatal("disabled cache affected runner startup")
	}
}

func TestCacheTransportLossDoesNotReattach(t *testing.T) {
	p, _, f := fixture(t, true)
	enableCache(t, p)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	stream, closed := cacheAgentFixture(t)
	opens := 0
	f.duplex = func(context.Context) (net.Conn, error) { opens++; return stream, nil }
	if err := p.prepareCache(t.Context(), spec().Name); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("guest listener survived stream loss")
	}
	if err := p.prepareCache(t.Context(), spec().Name); err != nil {
		t.Fatal(err)
	}
	if opens != 1 || len(f.calls) != 1 || !strings.HasSuffix(f.calls[0].command, "cache-setup") {
		t.Fatal("lost cache was reattached")
	}
}
