// Package winguest talks to the services already in a prepared Windows guest
// image over HvSocket: App Sandbox's guest agent, which enables OpenSSH and
// accepts a public key, and OpenSSH itself. A later increment replaces both
// with bivouac's own guest agent.
//
// Guest output is untrusted: only fixed protocol lines are interpreted, and no
// guest text reaches errors, logs or reports.
package winguest

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// The image's fixed HvSocket service IDs for the agent and OpenSSH.
const (
	AgentService = "a5b0cafe-0001-4000-8000-000000000001"
	SSHService   = "a5b0cafe-0007-4000-8000-000000000001"
)

// Agent reports what the guest agent confirmed during initialization.
type Agent struct {
	Connected   bool
	VDDAbsent   bool
	KeyDeployed bool
}

const (
	maxLine       = 4 << 10
	maxTranscript = 1 << 20
)

// Hello reads only the agent's greeting.
func Hello(ctx context.Context, conn net.Conn) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	line, err := readLine(ctx, bufio.NewReaderSize(conn, maxLine), conn)
	if err != nil {
		return err
	}
	if line != "hello" {
		return errors.New("unexpected guest agent greeting")
	}
	return nil
}

// Initialize declines GPU driver copies (prepared images already contain the
// host's drivers), enables guest SSH and deploys publicKey. It succeeds only
// once the agent confirms VDD is absent and acknowledges the key. Prepared
// images must retain Hyper-V synthetic video and cannot contain AppSandboxVDD.
func Initialize(ctx context.Context, conn net.Conn, publicKey []byte) (Agent, error) {
	var a Agent
	if len(publicKey) == 0 || len(publicKey) > 1024 || strings.ContainsAny(string(publicKey), "\r\n") {
		return a, errors.New("invalid SSH public key")
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	reader := bufio.NewReaderSize(conn, maxLine)
	hello, err := readLine(ctx, reader, conn)
	if err != nil {
		return a, err
	}
	if hello != "hello" {
		return a, errors.New("unexpected guest agent greeting")
	}
	a.Connected = true
	if err = write(ctx, conn, "gpu_none\n1:ssh_enable\n"); err != nil {
		return a, errors.New("guest agent initialization request failed")
	}
	keySent := false
	for read := 0; read < maxTranscript; {
		line, err := readLine(ctx, reader, conn)
		if err != nil {
			return a, err
		}
		read += len(line) + 1
		switch {
		case line == "gpu_query":
			if err = write(ctx, conn, "gpu_none\n"); err != nil {
				return a, errors.New("guest agent GPU response failed")
			}
		case line == "idd_status:not_found":
			a.VDDAbsent = true
		case strings.HasPrefix(line, "idd_status:"):
			return a, errors.New("guest agent did not confirm VDD absence")
		case line == "hyperv_video:disabled":
			return a, errors.New("guest agent disabled synthetic video")
		case line == "ssh_ready" || line == "1:ssh_ready":
			if !keySent {
				// The agent's key-deployment message, not a shell command.
				if err = write(ctx, conn, "ssh_deploy_key "+string(publicKey)+"\n"); err != nil {
					return a, errors.New("guest public-key deployment failed")
				}
				keySent = true
			}
		case line == "ssh_key_deployed":
			if !keySent {
				return a, errors.New("unsolicited guest key acknowledgement")
			}
			a.KeyDeployed = true
		case line == "ssh_failed" || line == "1:ssh_failed" || line == "ssh_key_failed" || line == "service_stopping" || line == "os_shutdown":
			return a, errors.New("guest agent reported initialization failure")
		case strings.HasPrefix(line, "gpu_copy_") || strings.HasPrefix(line, "gpu_device_failed:"):
			return a, errors.New("guest agent attempted a GPU driver copy for a prepared image")
		}
		if a.KeyDeployed && a.VDDAbsent {
			return a, nil
		}
	}
	return a, errors.New("guest agent transcript exceeded bound")
}

func deadline(ctx context.Context, limit time.Duration) time.Time {
	d := time.Now().Add(limit)
	if c, ok := ctx.Deadline(); ok && c.Before(d) {
		return c
	}
	return d
}

func readLine(ctx context.Context, r *bufio.Reader, conn net.Conn) (string, error) {
	if err := conn.SetReadDeadline(deadline(ctx, 30*time.Second)); err != nil {
		return "", errors.New("guest agent read deadline unavailable")
	}
	b, err := r.ReadSlice('\n')
	if err != nil {
		return "", errors.New("guest agent line unavailable or exceeds 4 KiB")
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
}

func write(ctx context.Context, conn net.Conn, text string) error {
	if err := conn.SetWriteDeadline(deadline(ctx, 10*time.Second)); err != nil {
		return err
	}
	_, err := io.WriteString(conn, text)
	return err
}
