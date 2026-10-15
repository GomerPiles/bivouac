package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const GuestDir = "/tmp/bivouac-container"
const GuestSocket = GuestDir + "/api.sock"
const GuestHelper = "/tmp/bivouac-container-helper"

// PublicDNS changes only a disposable guest. The gateway is deliberately blocked,
// including its DNS service. Baselines must not restore a private DNS server.
func PublicDNS(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if runtime.GOOS == "darwin" {
		out, err := exec.CommandContext(ctx, "/usr/sbin/networksetup", "-listallnetworkservices").Output()
		if err != nil {
			return errors.New("list guest network services")
		}
		count := 0
		for _, s := range strings.Split(strings.TrimSpace(string(out)), "\n")[1:] {
			if s == "" || strings.HasPrefix(s, "*") {
				continue
			}
			if exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/networksetup", "-setdnsservers", s, "1.1.1.1", "8.8.8.8").Run() != nil {
				return errors.New("configure public guest DNS")
			}
			count++
		}
		if count == 0 {
			return errors.New("no guest network service")
		}
		return nil
	}
	if runtime.GOOS == "linux" {
		cmd := exec.CommandContext(ctx, "sudo", "-n", "tee", "/etc/resolv.conf")
		cmd.Stdin = strings.NewReader("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
		if os.Geteuid() == 0 {
			return os.WriteFile("/etc/resolv.conf", []byte("nameserver 1.1.1.1\nnameserver 8.8.8.8\n"), 0o600)
		}
		if cmd.Run() != nil {
			return errors.New("configure public guest DNS")
		}
		return nil
	}
	return errors.New("unsupported container guest OS")
}

// Socket is intentionally fixed, and is opened only by the Linux guest helper.
func Socket(engine string) (string, error) {
	switch engine {
	case "docker":
		return "/var/run/docker.sock", nil
	case "podman":
		return "/run/podman/podman.sock", nil
	}
	return "", errors.New("unknown container engine")
}

type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error                { return errors.Join(os.Stdin.Close(), os.Stdout.Close()) }

// GuestListen runs on macOS, in the same user session as the runner.
func GuestListen(ctx context.Context) error {
	if runtime.GOOS != "darwin" {
		return errors.New("container listener requires a macOS guest")
	}
	if err := os.MkdirAll(GuestDir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(GuestDir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		return errors.New("container socket directory must be private")
	}
	// Do not remove an existing socket: a second relay must fail closed.
	l, err := net.Listen("unix", GuestSocket)
	if err != nil {
		return errors.New("container listener unavailable")
	}
	if err = os.Chmod(GuestSocket, 0o600); err != nil {
		_ = l.Close()
		return err
	}
	return Listen(ctx, stdio{}, l)
}

// GuestDial is invoked through the guest agent in the disposable Linux engine VM.
func GuestDial(ctx context.Context, engine string) error {
	if runtime.GOOS != "linux" {
		return errors.New("container dial requires a Linux guest")
	}
	path, err := Socket(engine)
	if err != nil {
		return err
	}
	c, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return errors.New("linux engine socket unavailable")
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.Close(); _ = os.Stdin.Close() })
	defer stop()
	done := make(chan error, 1)
	go func() {
		_, e := io.Copy(c, os.Stdin)
		if half, ok := c.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		done <- e
	}()
	_, err = io.Copy(os.Stdout, c)
	_ = c.Close()
	_ = os.Stdin.Close()
	<-done
	return err
}

// Probe verifies an end-to-end engine response without running a container.
func Probe(ctx context.Context, path string) error {
	t := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", path)
	}}
	defer t.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://engine/_ping", nil)
	if err != nil {
		return err
	}
	r, err := (&http.Client{Transport: t, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return errors.New("container engine probe failed")
	}
	defer func() { _ = r.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(r.Body, 3))
	if err != nil || r.StatusCode != http.StatusOK || string(b) != "OK" {
		return errors.New("invalid container engine probe response")
	}
	return nil
}
