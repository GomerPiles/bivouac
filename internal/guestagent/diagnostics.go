package guestagent

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"regexp"
	"sync"

	"github.com/GomerPiles/bivouac/internal/redact"
)

// DiagnosticStderr is an opt-in sink for trusted lab commands. It redacts before
// retaining a bounded prefix, drains excess output, and never changes command
// success because diagnostics were truncated. The caller closes it after the
// command/stream reader has finished, then logs Text only on failure.
type DiagnosticStderr struct {
	sink      *redact.Writer
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func NewDiagnosticStderr() *DiagnosticStderr {
	d := &DiagnosticStderr{}
	d.sink = redact.NewWriter(diagnosticPrefix{d})
	return d
}
func (d *DiagnosticStderr) Write(p []byte) (int, error) { return d.sink.Write(p) }
func (d *DiagnosticStderr) Close() error                { return d.sink.Close() }
func (d *DiagnosticStderr) Text() (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Panic stacks can contain the build machine's checkout path. Keep public
	// fixture diagnostics independent of personal filesystem locations.
	paths := regexp.MustCompile(`(?:[A-Za-z]:[\\/]|/(?:Users|home|private|var/folders)/)[^\s"'<>]+`)
	urls := regexp.MustCompile(`https?://[^\s"'<>]+`)
	return urls.ReplaceAllString(paths.ReplaceAllString(string(d.data), "<path>"), "<url>"), d.truncated
}

type diagnosticPrefix struct{ owner *DiagnosticStderr }

func (w diagnosticPrefix) Write(p []byte) (int, error) {
	d := w.owner
	d.mu.Lock()
	defer d.mu.Unlock()
	const limit = 8 << 10
	n := min(len(p), limit-len(d.data))
	d.data = append(d.data, p[:n]...)
	d.truncated = d.truncated || n < len(p)
	return len(p), nil
}

// DiagnosticError reports fixed categories and numeric exit codes, never the
// error's text, arguments, paths, addresses or guest-controlled failure payload.
func DiagnosticError(err error) (string, int) {
	var guestExit *ExitError
	var hostExit *exec.ExitError
	var version *VersionError
	var network net.Error
	switch {
	case err == nil:
		return "none", 0
	case errors.As(err, &guestExit):
		return "guest_exit", guestExit.Code
	case errors.As(err, &hostExit):
		return "host_exit", hostExit.ExitCode()
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline", -1
	case errors.Is(err, context.Canceled):
		return "canceled", -1
	case errors.Is(err, ErrUnavailable):
		return "agent_unavailable", -1
	case errors.Is(err, ErrFailed):
		return "agent_failed", -1
	case errors.As(err, &version):
		return "agent_version", -1
	case errors.As(err, &network):
		if network.Timeout() {
			return "network_timeout", -1
		}
		return "network", -1
	default:
		return "other", -1
	}
}
