package winguest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const testKey = "ssh-ed25519 synthetic-public-key"

func agentTest(t *testing.T, script func(net.Conn) error) (Agent, error) {
	t.Helper()
	host, guest := net.Pipe()
	defer func() { _ = host.Close() }()
	done := make(chan error, 1)
	go func() { defer func() { _ = guest.Close() }(); done <- script(guest) }()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	a, err := Initialize(ctx, host, []byte(testKey))
	_ = host.Close()
	if scriptErr := <-done; scriptErr != nil && !errors.Is(scriptErr, io.ErrClosedPipe) {
		t.Fatal(scriptErr)
	}
	return a, err
}

func readInitialization(conn net.Conn) (*bufio.Reader, error) {
	if _, err := io.WriteString(conn, "hello\n"); err != nil {
		return nil, err
	}
	r := bufio.NewReader(conn)
	for _, expected := range []string{"gpu_none\n", "1:ssh_enable\n"} {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line != expected {
			return nil, fmt.Errorf("unexpected fixed initialization %q", line)
		}
	}
	return r, nil
}

func TestAgentRequiresVDDAbsenceAndAcknowledgedPublicKey(t *testing.T) {
	a, err := agentTest(t, func(conn net.Conn) error {
		r, err := readInitialization(conn)
		if err != nil {
			return err
		}
		if _, err = io.WriteString(conn, "heartbeat\nlog:discard-this-output\ngpu_query\n"); err != nil {
			return err
		}
		if line, err := r.ReadString('\n'); err != nil || line != "gpu_none\n" {
			return fmt.Errorf("GPU query not declined: %q: %w", line, err)
		}
		if _, err = io.WriteString(conn, "idd_status:not_found\n1:ssh_ready\n"); err != nil {
			return err
		}
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if line != "ssh_deploy_key "+testKey+"\n" {
			return errors.New("unexpected key protocol")
		}
		_, err = io.WriteString(conn, "ssh_key_deployed\n")
		return err
	})
	if err != nil || !a.Connected || !a.VDDAbsent || !a.KeyDeployed {
		t.Fatalf("agent initialization: %+v %v", a, err)
	}
}

func TestAgentRejectsUnsolicitedKeyFailuresAndDriverCopies(t *testing.T) {
	for _, message := range []string{"ssh_key_deployed", "ssh_failed", "os_shutdown", "gpu_copy_error:guest-private-output", "gpu_device_failed:guest-private-output", "gpu_copy_done:1"} {
		t.Run(strings.SplitN(message, ":", 2)[0], func(t *testing.T) {
			_, err := agentTest(t, func(conn net.Conn) error {
				if _, err := readInitialization(conn); err != nil {
					return err
				}
				_, err := io.WriteString(conn, message+"\n")
				return err
			})
			if err == nil || strings.Contains(err.Error(), "guest-private-output") {
				t.Fatalf("unsafe agent failure: %v", err)
			}
		})
	}
}

func TestAgentBoundsUnterminatedOutput(t *testing.T) {
	_, err := agentTest(t, func(conn net.Conn) error {
		_, _ = io.WriteString(conn, strings.Repeat("x", 5000))
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "4 KiB") {
		t.Fatalf("overlong greeting accepted: %v", err)
	}
}

func TestAgentCancellationClosesBlockedTransport(t *testing.T) {
	host, guest := net.Pipe()
	defer func() { _ = guest.Close() }()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := Initialize(ctx, host, []byte(testKey)); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation leaked reader")
	}
}

func TestInvalidPublicKeyIsRefusedBeforeIO(t *testing.T) {
	host, guest := net.Pipe()
	defer func() { _ = host.Close(); _ = guest.Close() }()
	for _, key := range []string{"", "ssh-ed25519 a\nssh_deploy_key injected"} {
		if _, err := Initialize(t.Context(), host, []byte(key)); err == nil {
			t.Fatalf("accepted %q", key)
		}
	}
}

func TestHelloReadsOnlyTheGreeting(t *testing.T) {
	host, guest := net.Pipe()
	defer func() { _ = host.Close(); _ = guest.Close() }()
	go func() { _, _ = io.WriteString(guest, "hello\n") }()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := Hello(ctx, host); err != nil {
		t.Fatal(err)
	}
}
