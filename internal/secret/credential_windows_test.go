//go:build windows

package secret

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

type credentialFixture struct {
	target string
	value  []byte
	err    error
	calls  int
}

func (f *credentialFixture) read(target string) ([]byte, error) {
	f.calls++
	f.target = target
	return bytes.Clone(f.value), f.err
}

func (f *credentialFixture) write(target string, value []byte) error {
	f.calls++
	f.target, f.value = target, bytes.Clone(value)
	return f.err
}

func (f *credentialFixture) delete(target string) error {
	f.calls++
	f.target = target
	return f.err
}

func TestCredentialNamesAndLimits(t *testing.T) {
	ctx := context.Background()
	f := &credentialFixture{}
	c := CredentialManager{api: f}
	for _, name := range []string{"", "../item", "/item", ".item", "with space", "a\x00b", strings.Repeat("a", 129)} {
		if _, err := c.Get(ctx, name); err == nil {
			t.Fatal("accepted invalid name")
		}
		if err := c.Set(ctx, name, []byte{1}); err == nil {
			t.Fatal("accepted invalid name")
		}
		if err := c.Delete(ctx, name); err == nil {
			t.Fatal("accepted invalid name")
		}
	}
	for _, value := range [][]byte{nil, make([]byte, maxCredentialBytes+1)} {
		if err := c.Set(ctx, "item", value); err == nil {
			t.Fatal("accepted invalid size")
		}
	}
	if f.calls != 0 {
		t.Fatal("validation invoked native backend")
	}
	value := bytes.Repeat([]byte{0, 255, 10, 1}, maxCredentialBytes/4)
	if err := c.Set(ctx, "github-app-key", value); err != nil {
		t.Fatal(err)
	}
	if f.target != "bivouac/github-app-key" || !bytes.Equal(f.value, value) {
		t.Fatal("wrong target or bytes")
	}
	out, err := c.Get(ctx, "github-app-key")
	if err != nil || !bytes.Equal(out, value) {
		t.Fatal("get did not preserve bytes")
	}
	out[0] = 1
	if f.value[0] != 0 {
		t.Fatal("shared output memory")
	}
	if err := c.Delete(ctx, "github-app-key"); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &credentialFixture{}
	c := CredentialManager{api: f}
	if _, err := c.Get(ctx, "item"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := c.Set(ctx, "item", []byte{1}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, "item"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.calls != 0 {
		t.Fatal("cancelled request invoked native backend")
	}
}

func TestCredentialErrorMapping(t *testing.T) {
	if !errors.Is(credentialError("read", windows.ERROR_NOT_FOUND), ErrNotFound) {
		t.Fatal("missing item mapping")
	}
	if !errors.Is(credentialError("write", windows.ERROR_ACCESS_DENIED), windows.ERROR_ACCESS_DENIED) {
		t.Fatal("native error lost")
	}
	if _, ok := Default().(CredentialManager); !ok {
		t.Fatal("wrong Windows default")
	}
}

// Explicit opt-in: writes only a randomly named fixture containing synthetic
// bytes, then deletes it. Never enumerates or reads existing credentials.
func TestNativeCredentialRoundTrip(t *testing.T) {
	if os.Getenv("BIVOUAC_WINDOWS_CREDENTIAL_TEST") != "1" {
		t.Skip("native credential fixture requires explicit opt-in")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	name := "test-" + hex.EncodeToString(id)
	c := CredentialManager{}
	ctx := context.Background()
	t.Cleanup(func() {
		if err := c.Delete(ctx, name); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("fixture cleanup: %v", err)
		}
	})
	if _, err := c.Get(ctx, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("initial lookup: %v", err)
	}
	for _, value := range [][]byte{[]byte("synthetic\x00fixture\n"), bytes.Repeat([]byte{0, 255}, maxCredentialBytes/2)} {
		if err := c.Set(ctx, name, value); err != nil {
			t.Fatal(err)
		}
		out, err := c.Get(ctx, name)
		if err != nil || !bytes.Equal(out, value) {
			t.Fatalf("round trip mismatch: %v", err)
		}
	}
	if err := c.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted lookup: %v", err)
	}
	if err := c.Delete(ctx, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted item: %v", err)
	}
}
