//go:build windows

package hcsspike

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

func agentTest(t *testing.T, script func(net.Conn) error) (Report, error) {
	t.Helper()
	return agentTestConfig(t, exampleConfig(), script)
}
func agentTestConfig(t *testing.T, c Config, script func(net.Conn) error) (Report, error) {
	t.Helper()
	host, guest := net.Pipe()
	defer func() { _ = host.Close() }()
	done := make(chan error, 1)
	go func() { defer func() { _ = guest.Close() }(); done <- script(guest) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	report, err := speakAgent(ctx, host, c, []byte("ssh-ed25519 synthetic-public-key"))
	_ = host.Close()
	if scriptErr := <-done; scriptErr != nil {
		t.Fatal(scriptErr)
	}
	return report, err
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

func TestAgentRequiresDisplayAndAcknowledgedPublicKey(t *testing.T) {
	report, err := agentTest(t, func(conn net.Conn) error {
		r, err := readInitialization(conn)
		if err != nil {
			return err
		}
		if _, err = io.WriteString(conn, "heartbeat\nlog:discard-this-output\nidd_status:ok\n1:ssh_ready\n"); err != nil {
			return err
		}
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if line != "ssh_deploy_key ssh-ed25519 synthetic-public-key\n" {
			return errors.New("unexpected key protocol")
		}
		_, err = io.WriteString(conn, "ssh_key_deployed\n")
		return err
	})
	if err != nil || !report.AgentConnected || !report.DisplayReady {
		t.Fatalf("agent initialization: %+v %v", report, err)
	}
	if report.SSHAuthenticated {
		t.Fatal("agent acknowledgement was mistaken for SSH authentication")
	}
}

func TestAgentRejectsUnsolicitedKeyAndGPUFailure(t *testing.T) {
	for _, message := range []string{"ssh_key_deployed", "gpu_copy_error:guest-private-output", "gpu_device_failed:guest-private-output"} {
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
		if _, err := io.WriteString(conn, strings.Repeat("x", 5000)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			return err
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "4 KiB") {
		t.Fatalf("overlong greeting accepted: %v", err)
	}
}

func TestGPUProtocolUsesOnlyValidatedDestinations(t *testing.T) {
	c := exampleConfig()
	c.Drivers = []DriverShare{{Source: `C:\Tests\Drivers\vendor`, GuestPath: `C:\Windows\HostDriverStore\FileRepository\vendor`}}
	var out strings.Builder
	if err := writeGPU(&out, c); err != nil {
		t.Fatal(err)
	}
	expected := "gpu_query_response:1\nAppSandbox.Drv.0|C:\\Windows\\HostDriverStore\\FileRepository\\vendor|\n"
	if out.String() != expected || strings.Contains(out.String(), c.Drivers[0].Source) {
		t.Fatal("driver protocol differs or exposes host source")
	}
}

func TestAgentCancellationClosesBlockedTransport(t *testing.T) {
	host, guest := net.Pipe()
	defer func() { _ = guest.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := speakAgent(ctx, host, exampleConfig(), nil); done <- err }()
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

func TestAgentWaitsForDriverCopyBeforeDeclaringReady(t *testing.T) {
	c := exampleConfig()
	c.GPU = true
	c.Drivers = []DriverShare{{Source: `C:\Fixture\Drivers`, GuestPath: `C:\Windows\HostDriverStore\FileRepository\fixture`}}
	report, err := agentTestConfig(t, c, func(conn net.Conn) error {
		if _, err := io.WriteString(conn, "hello\n"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		for _, expected := range []string{"gpu_query_response:1\n", "AppSandbox.Drv.0|C:\\Windows\\HostDriverStore\\FileRepository\\fixture|\n", "1:ssh_enable\n"} {
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			if line != expected {
				return errors.New("unexpected driver initialization")
			}
		}
		if _, err := io.WriteString(conn, "idd_status:ok\n1:ssh_ready\n"); err != nil {
			return err
		}
		if _, err := reader.ReadString('\n'); err != nil {
			return err
		}
		if _, err := io.WriteString(conn, "ssh_key_deployed\n"); err != nil {
			return err
		}
		// A premature success closes the pipe before the delayed copy acknowledgement.
		time.Sleep(30 * time.Millisecond)
		_, err := io.WriteString(conn, "gpu_copy_done:1\n")
		return err
	})
	if err != nil || !report.AgentConnected || !report.DisplayReady {
		t.Fatalf("driver readiness: %v", err)
	}
}
