package appsandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/provider"
)

// A renamed test binary exercises the real subprocess boundary without
// contacting SSH, a native broker or any live guest.
func TestSSHCommandHelper(t *testing.T) {
	if os.Getenv("BIVOUAC_SSH_COMMAND_FIXTURE") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if mode == "hang" {
		time.Sleep(time.Hour)
	}
	if mode == "auth-hang" {
		_, _ = fmt.Fprint(os.Stderr, "Permission denied (publickey)")
		time.Sleep(time.Hour)
	}
	if mode == "exit-one" {
		os.Exit(1)
	}
	if mode == "overflow" {
		mode = strings.Repeat("x", 9<<10) + "Permission denied"
	}
	_, _ = fmt.Fprint(os.Stderr, mode)
	_, _ = fmt.Fprint(os.Stdout, "synthetic-private-output")
	os.Exit(255)
}

func TestNativeSSHFailuresAreBoundedAndClassified(t *testing.T) {
	t.Setenv("BIVOUAC_SSH_COMMAND_FIXTURE", "1")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	ssh := filepath.Join(t.TempDir(), "ssh.exe")
	// #nosec G306 -- This isolated fixture is an executable, readable only by its owner.
	if err := os.WriteFile(ssh, data, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		stderr string
		kind   provider.TransportFailure
	}{
		{"ssh: connect to host 127.0.0.1 port 2222: Connection refused", provider.SSHRefused},
		{"Connection timed out", provider.SSHTimeout},
		{"client_loop: send disconnect: Connection reset", provider.SSHReset},
		{"Connection closed by 127.0.0.1", provider.SSHClosed},
		{"Broken pipe", provider.SSHClosed},
		{"synthetic-private-error", provider.SSHUnavailable},
		{"", provider.SSHUnavailable},
		{"Permission denied (publickey). Connection reset", provider.SSHAuthentication},
		{"REMOTE HOST IDENTIFICATION HAS CHANGED! Connection closed", provider.SSHHostKey},
		{"Host key verification failed.", provider.SSHHostKey},
		{"Load key synthetic-key: invalid format", provider.SSHConfiguration},
		{"no matching key exchange method found", provider.SSHConfiguration},
		{"overflow", provider.SSHDiagnosticLimit},
	} {
		t.Run(tc.kind.Error()+tc.stderr, func(t *testing.T) {
			args := []string{"-test.run=^TestSSHCommandHelper$", "--", tc.stderr}
			out, err := (NativeCommands{}).Input(context.Background(), ssh, args, []byte("synthetic-private-input"))
			var kind provider.TransportFailure
			if !errors.As(err, &kind) || kind != tc.kind || len(out) != 0 {
				t.Fatal(kind, err)
			}
			if strings.Contains(err.Error(), "synthetic-") || !strings.Contains(err.Error(), "exit 255") {
				t.Fatal("raw subprocess data reached error", err)
			}
		})
	}
	for _, binary := range []string{ssh, self} {
		_, err := (NativeCommands{}).Output(context.Background(), binary, []string{"-test.run=^TestSSHCommandHelper$", "--", "exit-one"})
		var kind provider.TransportFailure
		if err == nil || errors.As(err, &kind) {
			t.Fatal("non-transport exit became retryable", err)
		}
	}
	_, err = (NativeCommands{}).Output(context.Background(), self, []string{"-test.run=^TestSSHCommandHelper$", "--", "Connection reset"})
	var kind provider.TransportFailure
	if err == nil || errors.As(err, &kind) {
		t.Fatal("non-SSH native error became retryable", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = (NativeCommands{}).Output(ctx, ssh, []string{"-test.run=^TestSSHCommandHelper$", "--", "hang"})
	if !errors.As(err, &kind) || kind != provider.SSHTimeout {
		t.Fatal("hung SSH was not bounded", err)
	}
	authCtx, authCancel := context.WithTimeout(context.Background(), time.Second)
	defer authCancel()
	_, err = (NativeCommands{}).Output(authCtx, ssh, []string{"-test.run=^TestSSHCommandHelper$", "--", "auth-hang"})
	if !errors.As(err, &kind) || kind != provider.SSHAuthentication {
		t.Fatal("deadline hid terminal authentication diagnostic", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	_, err = (NativeCommands{}).Output(ctx, ssh, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation became a failure", err)
	}
}
