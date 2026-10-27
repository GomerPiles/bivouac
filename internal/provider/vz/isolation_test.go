package vz

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/vm"
)

func TestOrdinaryRunnerIsolationFailsBeforeCloneOrLaunch(t *testing.T) {
	p, r := ownedFixture(t)
	p.checkIsolation = func(context.Context) error { return errors.New("policy unavailable") }
	spec := provider.Spec{Name: "bivouac-macos-new", Baseline: "base", Meta: provider.Metadata{ControllerID: p.controllerID, InstanceID: "new"}}
	if p.Create(context.Background(), spec) == nil {
		t.Fatal("cloned without available policy")
	}
	if p.Start(context.Background(), fixtureName, io.Discard) == nil {
		t.Fatal("NAT fallback without available policy")
	}
	for _, call := range r.calls {
		if call[0] == "Clone" || call[0] == "Start" {
			t.Fatal("runtime mutated despite failed isolation")
		}
	}
}
func TestStaleOrMissingPolicyRefusesCredentialsAndAdoption(t *testing.T) {
	for _, policy := range []string{"", "@host", "@host,0.0.0.0/0", "rootless-public-ipv4"} {
		p, r := ownedFixture(t)
		m, _ := p.readMeta(fixtureName)
		m.NetworkPolicy = policy
		data, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(p.vmDir(fixtureName), markerFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if p.StartRunner(context.Background(), fixtureName, []byte("synthetic-private-jit")) == nil {
			t.Fatal("JIT accepted with stale policy")
		}
		if _, err := p.RunnerStatus(context.Background(), fixtureName); err == nil {
			t.Fatal("stale runner adopted")
		}
		for _, v := range r.stdin {
			if strings.Contains(v, "synthetic-private-jit") {
				t.Fatal("delivered private input")
			}
		}
		// A known owned old guest remains disposable, even when policy is obsolete.
		if err := p.Stop(context.Background(), fixtureName, 0); err != nil {
			t.Fatal(err)
		}
		if err := p.Delete(context.Background(), fixtureName); err != nil {
			t.Fatal(err)
		}
	}
}

type runtimeWithoutIsolationProof struct{ Runtime }

func TestRuntimeWithoutLiveIsolationProofCannotReceiveJIT(t *testing.T) {
	p, r := ownedFixture(t)
	p.rt = runtimeWithoutIsolationProof{p.rt}
	if err := p.StartRunner(context.Background(), fixtureName, []byte("synthetic-private-jit")); err == nil {
		t.Fatal("runtime without isolation proof accepted JIT")
	}
	if len(r.stdin) != 0 {
		t.Fatal("runtime received private input without live isolation proof")
	}
}

func TestLaunchArgsIsInformationalAndPreservesReadOnlyShare(t *testing.T) {
	p, _ := ownedFixture(t)
	shortStore, err := os.MkdirTemp("", "biv-launch-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortStore) })
	p.rt = &local{store: vm.Store(shortStore), exe: "unused"}
	p.cfg.BootstrapShare = t.TempDir()
	p.checkIsolation = func(context.Context) error {
		t.Fatal("informational launch arguments ran a host prerequisite probe")
		return nil
	}
	args, err := p.LaunchArgs(fixtureName)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := vm.ParseArgs(args[2:])
	if err != nil {
		t.Fatal(err)
	}
	if !opts.RootlessNetwork || !opts.Input || opts.Share != p.cfg.BootstrapShare {
		t.Fatal("ordinary runner lost isolation, input devices, or the read-only share")
	}
}
