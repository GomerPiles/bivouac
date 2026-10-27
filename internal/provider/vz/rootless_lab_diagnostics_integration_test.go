//go:build integration && darwin

package vz

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/rootnet"
)

func labFixtureFailure(t *testing.T, label string, err error, stderr *guestagent.DiagnosticStderr) {
	t.Helper()
	_ = stderr.Close()
	text, truncated := stderr.Text()
	class, code := guestagent.DiagnosticError(err)
	t.Logf("fixture_failure phase=%s error_class=%s exit_code=%d stderr_truncated=%t stderr=%q", label, class, code, truncated, text)
}

func labGuestDial(p *Provider, name string) (guestagent.Dialer, error) {
	meta, owned := p.owns(name)
	if !owned || !strings.HasPrefix(name, "bivouac-macos-rootless-lab-") || p.records == nil {
		return nil, errors.New("lab command ownership unavailable")
	}
	record, ok := p.records.Get(name)
	if !ok || record.Name != name || record.ID != meta.InstanceID || record.Provider != p.name {
		return nil, errors.New("lab command record differs")
	}
	if meta.NetworkPolicy == rootnet.PolicyID {
		if err := p.runnerIsolation(name); err != nil {
			return nil, err
		}
	} else if meta.NetworkPolicy != "" || os.Getenv("BIVOUAC_ROOTLESS_NAT_BENCHMARK") != "1" {
		return nil, errors.New("lab network policy differs")
	}
	rt, ok := p.rt.(*local)
	if !ok {
		return nil, errors.New("lab diagnostics require the local runtime")
	}
	return rt.dial(name)
}

func labExec(t *testing.T, ctx context.Context, p *Provider, name, phase string, argv []string, input io.Reader, output io.Writer) error {
	t.Helper()
	stderr := guestagent.NewDiagnosticStderr()
	defer func() { _ = stderr.Close() }()
	dial, err := labGuestDial(p, name)
	if err == nil {
		err = guestagent.RunWithStderr(ctx, dial, argv, input, output, stderr)
	}
	if err != nil {
		labFixtureFailure(t, phase, err, stderr)
	}
	return err
}

func labDuplex(t *testing.T, ctx context.Context, p *Provider, name, phase string, argv []string) (net.Conn, *guestagent.DiagnosticStderr, error) {
	t.Helper()
	stderr := guestagent.NewDiagnosticStderr()
	dial, err := labGuestDial(p, name)
	var stream net.Conn
	if err == nil {
		stream, err = guestagent.DuplexWithStderr(ctx, dial, argv, stderr)
	}
	if err != nil {
		labFixtureFailure(t, phase, err, stderr)
	}
	return stream, stderr, err
}
