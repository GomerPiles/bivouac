//go:build windows

package hcsvm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/provider"
)

// hvTransport retains only a per-guest dialer. Each command owns one connection.
// Admission by the VM's connect descriptor is authentication.
type hvTransport struct{}

func NewTransport() Transport { return hvTransport{} }

func (hvTransport) Open(_ context.Context, runtimeID string) (Session, error) {
	return &agentSession{dial: func(ctx context.Context) (net.Conn, error) {
		return guestagent.DialHvsockObserved(runtimeID, func() {
			if t := contextTiming(ctx); t != nil && t.step == stepAgentDial {
				t.report.SpansMS["agent_dial_retries"]++
			}
		})(ctx)
	}}, nil
}

type agentSession struct{ dial guestagent.Dialer }

// Version refusal is terminal, including during status grace. Is preserves the
// unavailable category without advertising a retryable TransportFailure.
type agentVersionRefusal struct{}

func (agentVersionRefusal) Error() string {
	return "guest agent unavailable: incompatible protocol version"
}
func (agentVersionRefusal) Is(err error) bool { return err == provider.GuestAgentUnavailable }

func agentError(ctx context.Context, err error) error {
	var version *guestagent.VersionError
	var exit *guestagent.ExitError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &version):
		return agentVersionRefusal{}
	case errors.As(err, &exit):
		return fmt.Errorf("guest command failed (exit %d)", exit.Code)
	case ctx.Err() != nil:
		return errors.Join(provider.GuestAgentTimeout, ctx.Err())
	case errors.Is(err, guestagent.ErrUnavailable):
		return provider.GuestAgentUnavailable
	default:
		return errors.New("guest agent command failed")
	}
}

type boundedOutput struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.overflow = true
		return 0, errors.New("guest command output exceeds bound")
	}
	return b.Buffer.Write(p)
}
func (s *agentSession) Run(ctx context.Context, argv []string, stdin io.Reader, limit int) ([]byte, error) {
	out := &boundedOutput{limit: limit}
	dial := s.dial
	if len(argv) == 2 && argv[0] == guestagent.WindowsPath && argv[1] == "version" {
		if t := contextTiming(ctx); t != nil {
			if _, ok := t.report.SpansMS["agent_dial_retries"]; !ok {
				t.report.SpansMS["agent_dial_retries"] = 0
			}
			dial = func(ctx context.Context) (net.Conn, error) {
				t.begin(stepAgentDial)
				conn, err := s.dial(ctx)
				if err == nil {
					t.begin(stepAgentProof)
				}
				return conn, err
			}
		}
	}
	err := guestagent.Run(ctx, dial, argv, stdin, out)
	if out.overflow {
		return nil, errors.New("guest command output exceeds bound")
	}
	if err != nil {
		return nil, agentError(ctx, err)
	}
	return out.Bytes(), nil
}
func (s *agentSession) Duplex(ctx context.Context, argv []string) (net.Conn, error) {
	conn, err := guestagent.Duplex(ctx, s.dial, argv)
	return conn, agentError(ctx, err)
}
func (*agentSession) Close() error { return nil }

func guestCommand(mode string) []string { return []string{guestHelper, "guest", "windows", mode} }

func proveAgent(ctx context.Context, s Session) error {
	for {
		attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
		_, err := s.Run(attempt, []string{guestagent.WindowsPath, "version"}, nil, 4096)
		cancel()
		var version agentVersionRefusal
		if err == nil || errors.As(err, &version) {
			return err
		}
		if ctx.Err() != nil {
			return errors.Join(provider.GuestAgentTimeout, ctx.Err())
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(provider.GuestAgentTimeout, ctx.Err())
		case <-timer.C:
		}
	}
}

func sendBytes(ctx context.Context, s Session, name string, data []byte) error {
	digest := sha256.Sum256(data)
	return receive(ctx, s, name, bytes.NewReader(data), int64(len(data)), hex.EncodeToString(digest[:]))
}
func receive(ctx context.Context, s Session, name string, data io.Reader, size int64, digest string) error {
	argv := []string{guestagent.WindowsPath, "guest-agent", "receive", name, strconv.FormatInt(size, 10), digest}
	_, err := s.Run(ctx, argv, data, 4096)
	return err
}
