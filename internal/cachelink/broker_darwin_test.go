package cachelink_test

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cachelink"
	"github.com/GomerPiles/bivouac/internal/rootnet"
)

func TestSandboxedCacheCapability(t *testing.T) {
	if len(os.Args) > 1 && os.Args[len(os.Args)-1] == "cache-capability-fixture" {
		code := func() int {
			f := os.NewFile(3, "cache-capability")
			defer func() { _ = f.Close() }()
			client, err := cachelink.NewClient(f)
			if err != nil {
				return 1
			}
			defer func() { _ = client.Close() }()
			if rootnet.ApplySandbox() != nil {
				return 2
			}
			conn, err := client.Dial(context.Background(), cachelink.Payload)
			if err != nil {
				return 3
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write([]byte("echo")); err != nil {
				return 4
			}
			var b [4]byte
			if _, err := io.ReadFull(conn, b[:]); err != nil || string(b[:]) != "echo" {
				return 5
			}
			if _, err := os.ReadFile("/etc/hosts"); err == nil {
				return 6
			}
			return 0
		}()
		os.Exit(code)
	}
	dir, err := os.MkdirTemp("/tmp", "biv-cache-cap-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "b.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err == nil {
			defer func() { _ = c.Close() }()
			_, _ = io.Copy(c, c)
		}
	}()
	b, fd, err := cachelink.NewBroker(path, path, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close(); <-done }()
	defer func() { _ = fd.Close() }()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestSandboxedCacheCapability$", "--", "cache-capability-fixture")
	cmd.ExtraFiles = []*os.File{fd}
	cmd.Env = []string{"HOME=/"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sandbox cache capability: %v %s", err, out)
	}
}

func TestBrokerBudgetAndRevocation(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "biv-cache-budget-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "b.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Conn, 32+cachelink.MaxRevocationConnections)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	broker, fd, err := cachelink.NewBroker(path, path, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = broker.Close() }()
	defer func() { _ = fd.Close() }()
	client, err := cachelink.NewClient(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
		_ = listener.Close()
		<-done
		close(accepted)
		for c := range accepted {
			_ = c.Close()
		}
	}()
	for range 32 {
		c, err := client.Dial(context.Background(), cachelink.Payload)
		if err != nil {
			t.Fatal("cache budget refused early")
		}
		conns = append(conns, c)
	}
	if c, err := client.Dial(context.Background(), cachelink.Payload); err == nil {
		_ = c.Close()
		t.Fatal("cache budget exceeded")
	}
	for range cachelink.MaxRevocationConnections {
		c, err := client.Dial(context.Background(), cachelink.Revocation)
		if err != nil {
			t.Fatal("payload saturation consumed broker revocation budget")
		}
		conns = append(conns, c)
	}
	if c, err := client.Dial(context.Background(), cachelink.Revocation); err == nil {
		_ = c.Close()
		t.Fatal("revocation budget exceeded")
	}
	_ = broker.Close()
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err := c.Read(b[:]); err == nil {
			t.Fatal("revoked capability stayed open")
		}
	}
}

func TestDisabledBrokerCannotOpenBackend(t *testing.T) {
	broker, fd, err := cachelink.NewBroker("", "", 32)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = broker.Close() }()
	defer func() { _ = fd.Close() }()
	client, err := cachelink.NewClient(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if client.Enabled() {
		t.Fatal("disabled cache admitted capability")
	}
	if c, err := client.Dial(context.Background(), cachelink.Payload); err == nil {
		_ = c.Close()
		t.Fatal("disabled cache connected")
	}
}

func TestBrokerRelayHalfClose(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "child", true: "backend"}[reverse], func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "biv-relay-")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.RemoveAll(dir) }()
			path := filepath.Join(dir, "cache.sock")
			l, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = l.Close() }()
			broker, fd, err := cachelink.NewBroker(path, path, 2)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = broker.Close() }()
			defer func() { _ = fd.Close() }()
			client, err := cachelink.NewClient(fd)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			a, err := client.Dial(context.Background(), cachelink.Payload)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = a.Close() }()
			b, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = b.Close() }()
			if reverse {
				a, b = b, a
			}
			_ = a.SetDeadline(time.Now().Add(5 * time.Second))
			_ = b.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(a, "before"); err != nil {
				t.Fatal(err)
			}
			if err := a.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(b)
			if err != nil || string(data) != "before" {
				t.Fatal("first half-close lost data", err)
			}
			if _, err := io.WriteString(b, "after"); err != nil {
				t.Fatal(err)
			}
			if err := b.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			data, err = io.ReadAll(a)
			if err != nil || string(data) != "after" {
				t.Fatal("second direction lost data after FIN", err)
			}
		})
	}
}
