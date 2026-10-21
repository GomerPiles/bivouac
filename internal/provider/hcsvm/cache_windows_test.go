//go:build windows

package hcsvm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"github.com/GomerPiles/bivouac/internal/vmhost"
	"golang.org/x/crypto/ssh"
)

// cacheClientFixture authenticates real SSH and permits only the cache's
// guest-loopback listener request. HTTP forwarding is covered in cache tests.
func cacheClientFixture(t *testing.T) (*ssh.Client, <-chan struct{}) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal("fixture signer unavailable")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) {
			return nil, errors.New("fixture key refused")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		socket, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = socket.Close() }()
		conn, channels, requests, err := ssh.NewServerConn(socket, config)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		go func() {
			for channel := range channels {
				_ = channel.Reject(ssh.Prohibited, "fixture has no command service")
			}
		}()
		for request := range requests {
			var binding struct {
				Address string
				Port    uint32
			}
			if request.Type == "tcpip-forward" && ssh.Unmarshal(request.Payload, &binding) == nil && binding.Address == "127.0.0.1" && binding.Port == 0 {
				_ = request.Reply(true, ssh.Marshal(struct{ Port uint32 }{43210}))
			} else {
				_ = request.Reply(false, nil)
			}
		}
	}()
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "ciuser", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal("fixture authentication failed")
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, closed
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
			client, closed := cacheClientFixture(t)
			f.cacheClient = func(context.Context) (*ssh.Client, error) { return client, nil }
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
				want = append(want, guestHelper+" guest windows seed-jit", control+"start")
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
			client, closed := cacheClientFixture(t)
			f.cacheClient = func(context.Context) (*ssh.Client, error) { return client, nil }
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
			f.cacheClient = func(context.Context) (*ssh.Client, error) {
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
	f.cacheClient = func(context.Context) (*ssh.Client, error) {
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
