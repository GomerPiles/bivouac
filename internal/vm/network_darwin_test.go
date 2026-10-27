package vm

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/rootnet"
)

func TestNetworkChildLifecycle(t *testing.T) {
	if len(os.Args) > 1 && os.Args[len(os.Args)-1] == "network-child-fixture" {
		_ = RunNetwork(context.Background(), "02:00:00:00:00:02", config.VZNetwork{})
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestNetworkChildLifecycle$", "--", "network-child-fixture")
	child, attachment, err := startNetworkProcess(ctx, cmd, "", "", config.VZNetwork{}, 256)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	defer func() { _ = attachment.Close() }()
	if err := rootnet.SandboxedProcess(child.cmd.Process.Pid); err != nil {
		t.Fatal("live child sandbox proof:", err)
	}
	if err := child.lifetime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-child.done:
		_ = err
	case <-time.After(3 * time.Second):
		t.Fatal("child survived owner lifetime EOF")
	}
}

func TestNetworkChildMustSignalSandboxReadiness(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// This process exits without the private handshake and must never be accepted.
	cmd := exec.CommandContext(ctx, exe, "-test.run=^$")
	child, attachment, err := startNetworkProcess(ctx, cmd, "", "", config.VZNetwork{}, 256)
	if err == nil {
		child.Close()
		_ = attachment.Close()
		t.Fatal("child without sandbox readiness accepted")
	}
}
