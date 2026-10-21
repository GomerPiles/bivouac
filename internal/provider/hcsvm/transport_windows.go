//go:build windows

package hcsvm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/hvsock"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/winguest"
	"golang.org/x/crypto/ssh"
)

// hvTransport reaches a guest over HvSocket. Each session generates its own
// SSH identity in memory, deploys it through the guest agent and holds the
// agent session open for its life.
type hvTransport struct{ user string }

func NewTransport(user string) Transport { return hvTransport{user: user} }

func (t hvTransport) Open(ctx context.Context, name, runtimeID string, pin Pin) (Session, error) {
	vmID, err := hvsock.ParseGUID(runtimeID)
	if err != nil {
		return nil, errors.New("invalid guest runtime identity")
	}
	agentID, _ := hvsock.ParseGUID(winguest.AgentService)
	sshID, _ := hvsock.ParseGUID(winguest.SSHService)
	var agent net.Conn
	for agent == nil {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		agent, err = hvsock.Dial(attempt, hvsock.Addr{VMID: vmID, ServiceID: agentID})
		cancel()
		if agent != nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(provider.GuestAgentTimeout, err)
		case <-time.After(500 * time.Millisecond):
		}
	}
	id, err := winguest.NewIdentity()
	if err != nil {
		_ = agent.Close()
		return nil, err
	}
	s := &hvSession{agent: agent, id: id, address: hvsock.Addr{VMID: vmID, ServiceID: sshID}, user: t.user, pin: pin}
	fail := func(err error) (Session, error) {
		_ = s.Close()
		return nil, err
	}
	a, err := winguest.Initialize(ctx, agent, id.PublicKey)
	if err != nil {
		return fail(errors.Join(provider.GuestAgentUnavailable, err))
	}
	if !a.DisplayReady || !a.KeyDeployed {
		return fail(errors.New("guest agent did not confirm the display and SSH key"))
	}
	client, err := s.connect(ctx, nil)
	if err != nil {
		return fail(err)
	}
	s.client = client
	return s, nil
}

func (s *hvSession) connect(ctx context.Context, wrap func(net.Conn) net.Conn) (*ssh.Client, error) {
	var transport net.Conn
	transport, err := hvsock.Dial(ctx, s.address)
	if err != nil {
		return nil, provider.SSHUnavailable
	}
	if wrap != nil {
		transport = wrap(transport)
	}
	client, _, err := winguest.Connect(ctx, transport, s.user, s.id, s.pin.Check)
	switch {
	case errors.Is(err, winguest.ErrSSHHostKey) || errors.Is(err, provider.SSHHostKey):
		_ = transport.Close()
		return nil, provider.SSHHostKey
	case errors.Is(err, winguest.ErrSSHRejected):
		_ = transport.Close()
		return nil, provider.SSHAuthentication
	case err != nil:
		_ = transport.Close()
		return nil, provider.SSHUnavailable
	}
	return client, nil
}

type hvSession struct {
	agent   net.Conn
	id      *winguest.Identity
	client  *ssh.Client
	address hvsock.Addr
	user    string
	pin     Pin
	// Identity signing must finish before Close clears the private key.
	identityMu sync.Mutex
	closed     bool
}

func (s *hvSession) CacheClient(ctx context.Context, wrap func(net.Conn) net.Conn) (*ssh.Client, error) {
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	if s.closed {
		return nil, provider.SSHClosed
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return s.connect(ctx, wrap)
}

// Run reports a nonzero exit as a command failure and anything else as a
// retryable transport failure, so the manager's bounded grace applies.
func (s *hvSession) Run(ctx context.Context, command string, stdin []byte, limit int) ([]byte, error) {
	out, err := winguest.Run(ctx, s.client, command, stdin, limit)
	var exit *ssh.ExitError
	switch {
	case err == nil:
		return out, nil
	case errors.As(err, &exit):
		return nil, fmt.Errorf("guest command failed (exit %d)", exit.ExitStatus())
	case ctx.Err() != nil:
		return nil, errors.Join(provider.SSHTimeout, ctx.Err())
	default:
		return nil, provider.SSHClosed
	}
}

func (s *hvSession) Send(ctx context.Context, name string, data io.Reader, size int64) error {
	if err := winguest.Send(ctx, s.client, name, data, size); err != nil {
		if ctx.Err() != nil {
			return errors.Join(provider.SSHTimeout, ctx.Err())
		}
		return err
	}
	return nil
}

func (s *hvSession) Close() error {
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.client != nil {
		err = s.client.Close()
	}
	err = errors.Join(err, s.agent.Close())
	s.id.Clear()
	return err
}
