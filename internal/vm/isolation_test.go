package vm

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/rootnet"
)

func TestAdoptionRequiresRootlessLiveLaunch(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "guest")
	opts := RunOptions{Dir: dir, AgentPort: 1, AgentSocket: filepath.Join(os.TempDir(), "biv-guard.sock"), Input: true, RootlessNetwork: true}
	args := func(o RunOptions) []string { return append([]string{"bivouac", "vm", "run"}, o.Args()...) }
	if err := proveIsolationArgs(args(opts), dir, rootnet.PolicyID); err != nil {
		t.Fatal(err)
	}
	nat := opts
	nat.RootlessNetwork = false
	if proveIsolationArgs(args(nat), dir, rootnet.PolicyID) == nil {
		t.Fatal("adopted NAT")
	}
	if proveIsolationArgs(args(opts), dir, "obsolete-policy") == nil {
		t.Fatal("adopted different policy")
	}
	shared := opts
	shared.Share = dir
	if err := proveIsolationArgs(args(shared), dir, rootnet.PolicyID); err != nil {
		t.Fatal("read-only share changed network proof", err)
	}
}

func TestIsolationWithTypedNetworkSettings(t *testing.T) {
	opts := RunOptions{Dir: filepath.Join(t.TempDir(), "vm"), AgentSocket: filepath.Join(os.TempDir(), "biv-agent.sock"), AgentPort: 123, RootlessNetwork: true, Network: config.VZNetwork{DNSServers: []string{"127.0.0.1"}, MaxFlows: 8192, MemoryMB: 2048, MTU: 9000, TCPIdleTimeout: config.Duration{Duration: time.Hour}, UDPIdleTimeout: config.Duration{Duration: time.Minute}}, CacheMaxConnections: 512}
	parsed, err := ParseArgs(opts.Args())
	if err != nil || !reflect.DeepEqual(opts, parsed) {
		t.Fatal("typed network flags did not round trip", err)
	}
	if err := proveIsolationArgs(append([]string{"bivouac", "vm", "run"}, opts.Args()...), opts.Dir, rootnet.PolicyID); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkChildProofAcceptsOnlyTypedFlags(t *testing.T) {
	args := append([]string{"bivouac", "vm", "network", "02:00:00:00:00:02"}, NetworkArgs(config.VZNetwork{MTU: 9000, MaxFlows: 8192})...)
	if !networkChildArgs(args) {
		t.Fatal("typed child flags broke adoption proof")
	}
	if networkChildArgs(append(args, "--unproved")) || networkChildArgs([]string{"bivouac", "vm", "network", "invalid"}) {
		t.Fatal("unproved child command accepted")
	}
}
