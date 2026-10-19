// Package command runs fixed host or guest executables with argument arrays,
// bounded output and classified OpenSSH transport failures. It never invokes a
// shell, and subprocess output never reaches errors.
package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/GomerPiles/bivouac/internal/provider"
)

// DefaultLimit bounds stdout for Output and Input.
const DefaultLimit = 1 << 20

// Runner accepts argument arrays, never a shell command. Outputs are bounded
// and not included in errors: native diagnostics contain host metadata.
type Runner interface {
	Output(context.Context, string, []string) ([]byte, error)
}

// Native runs real subprocesses.
type Native struct{}

func (Native) Output(ctx context.Context, binary string, args []string) ([]byte, error) {
	return (Native{}).OutputLimit(ctx, binary, args, DefaultLimit)
}
func (Native) OutputLimit(ctx context.Context, binary string, args []string, limit int) ([]byte, error) {
	return run(ctx, binary, args, nil, limit)
}

// Input sends opaque JIT bytes to authenticated SSH stdin, never argv or logs.
func (Native) Input(ctx context.Context, binary string, args []string, data []byte) ([]byte, error) {
	return run(ctx, binary, args, bytes.NewReader(data), DefaultLimit)
}
func run(ctx context.Context, binary string, args []string, input io.Reader, limit int) ([]byte, error) {
	if limit < 1 || limit > 45<<20 {
		return nil, errors.New("invalid native output bound")
	}
	// #nosec G702 -- System vfpctrl/OpenSSH use fixed argument arrays; no shell or credential argument is used.
	cmd := exec.CommandContext(ctx, binary, args...)
	hideWindow(cmd)
	cmd.Stdin = input
	output := boundedOutput{limit: limit}
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	ssh := strings.EqualFold(filepath.Base(binary), "ssh.exe") || filepath.Base(binary) == "ssh"
	stderr := boundedOutput{limit: 8 << 10}
	if ssh {
		cmd.Stderr = &stderr
	}
	defer func() { clear(stderr.data) }()
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			if ssh && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				if kind := classifySSH(stderr); !kind.Retryable() {
					return nil, kind
				}
				return nil, provider.SSHTimeout
			}
			return nil, ctx.Err()
		}
		var status *exec.ExitError
		if errors.As(err, &status) {
			if ssh && status.ExitCode() == 255 {
				return nil, fmt.Errorf("SSH failed (exit 255): %w", classifySSH(stderr))
			}
			return nil, fmt.Errorf("native command %s failed (exit %d)", filepath.Base(binary), status.ExitCode())
		}
		return nil, errors.New("native command failed")
	}
	if output.overflow {
		return nil, errors.New("native filtering response exceeds bound")
	}
	return output.data, nil
}

// Do not retain arbitrary stderr, even after redaction. Truncation cannot prove
// the absence of a terminal authentication/key error, so it fails immediately.
func classifySSH(stderr boundedOutput) provider.TransportFailure {
	if stderr.overflow {
		return provider.SSHDiagnosticLimit
	}
	data := bytes.ToLower(stderr.data)
	defer clear(data)
	for _, pattern := range []string{"host key verification failed", "remote host identification has changed", "offending", "no matching host key", "revoked host key", "host key is revoked"} {
		if bytes.Contains(data, []byte(pattern)) {
			return provider.SSHHostKey
		}
	}
	for _, pattern := range []string{"no matching key exchange", "no matching cipher", "no matching mac", "bad configuration", "bad permissions", "load key", "identity file", "unknown option", "unknown configuration", "invalid format"} {
		if bytes.Contains(data, []byte(pattern)) {
			return provider.SSHConfiguration
		}
	}
	for _, pattern := range []string{"permission denied", "authentication failed", "authentication failures", "signing failed"} {
		if bytes.Contains(data, []byte(pattern)) {
			return provider.SSHAuthentication
		}
	}
	for _, entry := range []struct {
		pattern string
		kind    provider.TransportFailure
	}{
		{"timed out", provider.SSHTimeout},
		{"connection refused", provider.SSHRefused},
		{"connection reset", provider.SSHReset},
		{"connection closed", provider.SSHClosed},
		{"broken pipe", provider.SSHClosed},
	} {
		if bytes.Contains(data, []byte(entry.pattern)) {
			return entry.kind
		}
	}
	// OpenSSH uses 255 for transport failure (and can pass through a remote
	// 255). The fixed status command gets bounded grace for this ambiguity;
	// other exit codes and invalid responses remain terminal.
	return provider.SSHUnavailable
}

type boundedOutput struct {
	data     []byte
	overflow bool
	limit    int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	limit := b.limit
	if limit == 0 {
		limit = DefaultLimit
	}
	remaining := limit - len(b.data)
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	return n, nil
}
