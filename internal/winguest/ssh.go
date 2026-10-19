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

// Identity is a per-guest SSH client key that exists only in memory. The
// signer refers to the private key rather than copying it, so the key must
// outlive every signature: call Clear only once the identity is done.
type Identity struct {
	Signer    ssh.Signer
	PublicKey []byte // authorized_keys form, without a trailing newline
	private   ed25519.PrivateKey
}

func NewIdentity() (*Identity, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		clear(private)
		return nil, errors.New("cannot create SSH client identity")
	}
	return &Identity{Signer: signer, PublicKey: []byte(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))), private: private}, nil
}

// Clear zeroes the private key. The identity cannot sign afterwards.
func (i *Identity) Clear() { clear(i.private) }

// Connect authenticates over an HvSocket stream to the guest's SSH service.
// The stream's address is bound to one guest partition by the hypervisor, so
// a host key is accepted once verify reproves that partition. verify receives
// the key's SHA-256 fingerprint: the first connection records it, and later
// connections must present the same key.
func Connect(ctx context.Context, transport net.Conn, user string, id *Identity, verify func(fingerprint string) error) (*ssh.Client, string, error) {
	stop := context.AfterFunc(ctx, func() { _ = transport.Close() })
	defer stop()
	if d, ok := ctx.Deadline(); ok {
		if err := transport.SetDeadline(d); err != nil {
			return nil, "", errors.New("SSH transport deadline unavailable")
		}
	}
	var fingerprint string
	var verifyErr error
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(id.Signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			sum := sha256.Sum256(key.Marshal())
			if verifyErr = verify(hex.EncodeToString(sum[:])); verifyErr != nil {
				return verifyErr
			}
			fingerprint = hex.EncodeToString(sum[:])
			return nil
		},
	}
	conn, channels, requests, err := ssh.NewClientConn(transport, "guest", config)
	if err != nil {
		return nil, "", sshFailure(err, verifyErr, fingerprint != "")
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

// SSH handshake failures are reduced to the stage that failed. The library's
// error text can carry a server disconnect message, so it is never returned.
var (
	ErrSSHHandshake    = errors.New("guest SSH handshake failed before host key exchange")
	ErrSSHHostKey      = errors.New("guest SSH host key not accepted")
	ErrSSHRejected     = errors.New("guest SSH rejected the client key")
	ErrSSHAfterHostKey = errors.New("guest SSH handshake failed after host key exchange")
)

func sshFailure(err, verifyErr error, hostKeySeen bool) error {
	switch {
	case verifyErr != nil:
		return errors.Join(ErrSSHHostKey, verifyErr)
	case !hostKeySeen:
		return ErrSSHHandshake
	case strings.Contains(err.Error(), "unable to authenticate"):
		return ErrSSHRejected
	default:
		return ErrSSHAfterHostKey
	}
}
