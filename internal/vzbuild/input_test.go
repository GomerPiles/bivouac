package vzbuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

func inputPin(data []byte, urls ...string) vzrecipe.Input {
	sum := sha256.Sum256(data)
	return vzrecipe.Input{URLs: urls, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}
func TestVerifiedDownloadAndCacheReverification(t *testing.T) {
	data := []byte("pinned input")
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("download sent credentials")
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	pin := inputPin(data, server.URL)
	dir := t.TempDir()
	dst, err := obtain(context.Background(), dir, "", pin, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = obtain(context.Background(), dir, "", pin, server.Client()); err != nil || requests != 1 {
		t.Fatal("verified cache not reused", err)
	}
	if err = os.WriteFile(dst, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = obtain(context.Background(), dir, "", pin, server.Client()); err != nil || requests != 2 {
		t.Fatal("cache not reverified", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(b, data) {
		t.Fatal("download differs", err)
	}
	for _, kind := range []string{"size", "hash", "http", "credentials", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			p := pin
			switch kind {
			case "size":
				p.Size++
			case "hash":
				p.SHA256 = strings.Repeat("0", 64)
			case "http":
				p.URLs = []string{strings.Replace(server.URL, "https:", "http:", 1)}
			case "credentials":
				p.URLs = []string{"https://user:password@example.com/image"}
			case "oversize":
				p.Size--
			}
			if _, err := obtain(context.Background(), t.TempDir(), "", p, server.Client()); err == nil {
				t.Fatal("invalid input admitted")
			}
		})
	}
}
func TestLocalInputsAndAtomicFailure(t *testing.T) {
	data := []byte("local bytes")
	pin := inputPin(data, "https://example.com/pinned")
	local := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(local, data, 0600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := obtain(context.Background(), dir, local, pin, inputClient()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, append(data, 'x'), 0600); err != nil {
		t.Fatal(err)
	}
	failDir := t.TempDir()
	if _, err := obtain(context.Background(), failDir, local, pin, inputClient()); err == nil {
		t.Fatal("bad local input accepted")
	}
	entries, err := os.ReadDir(failDir)
	if err != nil || len(entries) != 0 {
		t.Fatal("unverified input published", err)
	}
	// Explicit local files are verified even when a good content-addressed copy exists.
	if _, err := obtain(context.Background(), dir, local, pin, inputClient()); err == nil {
		t.Fatal("local override bypassed pins")
	}
}
func TestRedirectRequiresHTTPS(t *testing.T) {
	client := inputClient()
	r, _ := http.NewRequest(http.MethodGet, "http://example.com/redirect", nil)
	if client.CheckRedirect(r, nil) == nil {
		t.Fatal("HTTP redirect accepted")
	}
}
func TestRecipeRegistryHasFreshValues(t *testing.T) {
	r := vzrecipe.Registry()
	r[0].Source.URLs[0] = "changed"
	if vzrecipe.Registry()[0].Source.URLs[0] == "changed" {
		t.Fatal("mutable registry global")
	}
}

func TestDownloadIdleTimeoutAllowsProgressAndCancelsStall(t *testing.T) {
	for _, stall := range []bool{false, true} {
		t.Run(map[bool]string{false: "progress", true: "stall"}[stall], func(t *testing.T) {
			data := []byte("abcde")
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "5")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				for _, b := range data {
					if stall {
						select {
						case <-r.Context().Done():
							return
						case <-time.After(time.Second):
						}
					} else {
						time.Sleep(20 * time.Millisecond)
					}
					if _, err := w.Write([]byte{b}); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}))
			defer server.Close()
			out, err := os.CreateTemp(t.TempDir(), "download")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = out.Close() }()
			err = downloadAttempt(context.Background(), server.Client(), server.URL, inputPin(data, server.URL), out, 60*time.Millisecond)
			if (err != nil) != stall {
				t.Fatal("wrong idle timeout result", err)
			}
		})
	}
	if inputClient().Timeout != 0 {
		t.Fatal("download retains a total timeout")
	}
}

func TestRecipePinsBootableQCOWSource(t *testing.T) {
	r := vzrecipe.Registry()[0]
	if r.Source.Size != 616522752 || r.Source.SHA256 != "50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e" {
		t.Fatal("qcow2 source pins changed")
	}
	for _, url := range r.Source.URLs {
		if !strings.HasSuffix(url, "/release-20261017/ubuntu-24.04-server-cloudimg-arm64.img") {
			t.Fatal("source is not the bootable qcow2 disk")
		}
	}
}
