package winguest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Identity is a per-guest SSH client key that exists only in memory.
type Identity struct {
	Signer    ssh.Signer
	PublicKey []byte // authorized_keys form, without a trailing newline
}

func NewIdentity() (Identity, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	defer clear(private)
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return Identity{}, errors.New("cannot create SSH client identity")
	}
	return Identity{Signer: signer, PublicKey: []byte(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))}, nil
}

// Connect authenticates over an HvSocket stream to the guest's SSH service.
// The stream's address is bound to one guest partition by the hypervisor, so
// the first host key is accepted once verify reproves that partition; its
// SHA-256 fingerprint is returned so callers can pin and compare it.
func Connect(ctx context.Context, transport net.Conn, user string, id Identity, verify func() error) (*ssh.Client, string, error) {
	stop := context.AfterFunc(ctx, func() { _ = transport.Close() })
	defer stop()
	if d, ok := ctx.Deadline(); ok {
		if err := transport.SetDeadline(d); err != nil {
			return nil, "", errors.New("SSH transport deadline unavailable")
		}
	}
	var fingerprint string
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(id.Signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if err := verify(); err != nil {
				return err
			}
			sum := sha256.Sum256(key.Marshal())
			fingerprint = hex.EncodeToString(sum[:])
			return nil
		},
	}
	conn, channels, requests, err := ssh.NewClientConn(transport, "guest", config)
	if err != nil {
		return nil, "", errors.New("guest SSH authentication failed")
	}
	// Clear the handshake deadline; each command sets its own bound.
	if err = transport.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, "", errors.New("SSH transport deadline unavailable")
	}
	return ssh.NewClient(conn, channels, requests), fingerprint, nil
}

// Run executes one fixed command, sending stdin and returning at most limit
// bytes of stdout. Stderr is discarded. Cancellation closes the client, since
// an SSH request cannot be withdrawn; nothing is replayed.
func Run(ctx context.Context, client *ssh.Client, command string, stdin []byte, limit int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()
	out := &limited{limit: limit}
	session.Stdin = bytes.NewReader(stdin)
	session.Stdout = out
	err = session.Run(command)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if out.overflow {
		return nil, errors.New("guest command output exceeds bound")
	}
	return out.data, err
}

type limited struct {
	data     []byte
	limit    int
	overflow bool
}

func (l *limited) Write(p []byte) (int, error) {
	if len(l.data)+len(p) > l.limit {
		l.overflow = true
		return 0, errors.New("guest command output exceeds bound")
	}
	l.data = append(l.data, p...)
	return len(p), nil
}
