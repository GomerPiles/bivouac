package winguest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// serve runs a one-connection SSH server that authorizes only allowed.
func serve(t *testing.T, conn net.Conn, allowed ssh.PublicKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if allowed != nil && bytes.Equal(key.Marshal(), allowed.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("synthetic-private-rejection")
	}}
	config.AddHostKey(signer)
	go func() {
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(requests)
		for c := range channels {
			_ = c.Reject(ssh.Prohibited, "no sessions")
		}
		_ = server.Close()
	}()
}

func connectFixture(t *testing.T, authorize bool, verify func() error) (string, error) {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer id.Clear()
	host, guest := tcpPair(t)
	var allowed ssh.PublicKey
	if authorize {
		allowed = id.Signer.PublicKey()
	}
	serve(t, guest, allowed)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, fingerprint, err := Connect(ctx, host, "ciuser", id, verify)
	if client != nil {
		_ = client.Close()
	}
	return fingerprint, err
}

// tcpPair is a connected loopback pair; SSH cannot handshake over net.Pipe,
// whose writes block until the peer reads.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			c = nil
		}
		accepted <- c
	}()
	host, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	guest := <-accepted
	if guest == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = host.Close(); _ = guest.Close() })
	return host, guest
}

func TestConnectReportsOnlyTheFailedStage(t *testing.T) {
	if fingerprint, err := connectFixture(t, true, func() error { return nil }); err != nil || len(fingerprint) != 64 {
		t.Fatal("authorized key refused", fingerprint, err)
	}
	if _, err := connectFixture(t, false, func() error { return nil }); !errors.Is(err, ErrSSHRejected) {
		t.Fatal("rejected key misclassified", err)
	}
	gone := errors.New("guest no longer running")
	if _, err := connectFixture(t, true, func() error { return gone }); !errors.Is(err, ErrSSHHostKey) || !errors.Is(err, gone) {
		t.Fatal("unverified partition accepted", err)
	}
	host, guest := net.Pipe()
	_ = guest.Close()
	id, _ := NewIdentity()
	if _, _, err := Connect(t.Context(), host, "ciuser", id, func() error { return nil }); !errors.Is(err, ErrSSHHandshake) {
		t.Fatal("transport loss misclassified", err)
	}
	for _, err := range []error{ErrSSHRejected, ErrSSHHostKey, ErrSSHHandshake, ErrSSHAfterHostKey} {
		if bytes.Contains([]byte(err.Error()), []byte("synthetic-private")) {
			t.Fatal("server text reached an error")
		}
	}
}

// Regression: an identity whose key was cleared on creation produced
// signatures the guest rejected, so every SSH login failed.
func TestIdentitySignsUntilCleared(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("synthetic session data")
	sig, err := id.Signer.Sign(rand.Reader, data)
	if err != nil || id.Signer.PublicKey().Verify(data, sig) != nil {
		t.Fatal("fresh identity cannot produce a verifiable signature", err)
	}
	id.Clear()
	if sig, err = id.Signer.Sign(rand.Reader, data); err == nil && id.Signer.PublicKey().Verify(data, sig) == nil {
		t.Fatal("cleared identity still signs with its key")
	}
}
