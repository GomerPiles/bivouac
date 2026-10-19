package appsandbox

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
)

type inputFixture struct {
	args  [][]string
	input []byte
}

type preflightFixture struct {
	inputFixture
	reply  string
	config []byte
}

func (f *preflightFixture) Output(_ context.Context, binary string, args []string) ([]byte, error) {
	f.args = append(f.args, slices.Clone(args))
	if binary == "scp" {
		for _, arg := range args {
			if strings.HasSuffix(arg, "bivouac-config.json") && !strings.Contains(arg, "@") {
				var err error
				f.config, err = os.ReadFile(arg)
				if err != nil {
					return nil, err
				}
			}
		}
		return nil, nil
	}
	return []byte(f.reply), nil
}

func TestGuestPreflightUsesFixedHvSocketTransportAndRejectsMissingConsole(t *testing.T) {
	_, _, _, record := engineFixture(t)
	for _, reply := range []string{`{"ready":true,"session":2}`, `{"ready":false,"session":2}`, `{"ready":true,"session":0}`, `{"ready":true,"session":4294967295}`, `{}`, `not-json`} {
		dir := t.TempDir()
		f := &preflightFixture{reply: reply}
		g := &SSHGuest{opts: GuestOptions{StateDir: dir, SSHBinary: "ssh", SCPBinary: "scp", SSHKey: "fixture-key"}, commands: f}
		lease := Lease{Record: record, SSH: SSH{Host: "127.0.0.1", Port: 2222, User: "ciuser", State: 4, Enabled: true, KeyDeployed: true}}
		err := g.Preflight(context.Background(), lease)
		if (err == nil) != (reply == `{"ready":true,"session":2}`) {
			t.Fatal("unproven console accepted or valid console rejected")
		}
		if !strings.Contains(string(f.config), record.NativeName) || strings.Contains(string(f.config), "fixture-key") {
			t.Fatal("preflight binding absent or credential staged")
		}
		last := f.args[len(f.args)-1]
		if !slices.Contains(last, "ciuser@127.0.0.1") || !slices.Contains(last, "bivouac-preflight.ps1") || slices.Contains(last, "prepare") {
			t.Fatal("preflight used wrong transport or networking operation")
		}
		files, err := os.ReadDir(dir)
		if err != nil || len(files) != 0 {
			t.Fatal("preflight host staging retained")
		}
	}
}

func (f *inputFixture) Output(_ context.Context, _ string, args []string) ([]byte, error) {
	f.args = append(f.args, slices.Clone(args))
	return []byte("started"), nil
}
func (f *inputFixture) Input(_ context.Context, _ string, args []string, input []byte) ([]byte, error) {
	f.args = append(f.args, slices.Clone(args))
	f.input = slices.Clone(input)
	return nil, nil
}
func TestJITUsesAuthenticatedStdinAndCreatesNoHostFile(t *testing.T) {
	_, _, _, record := engineFixture(t)
	dir := t.TempDir()
	commands := &inputFixture{}
	g := &SSHGuest{opts: GuestOptions{StateDir: dir, SSHBinary: "system-ssh", SSHKey: "fixture-key"}, commands: commands}
	lease := Lease{Record: record, SSH: SSH{Host: "127.0.0.1", Port: 2222, User: "ciuser", State: 4, Enabled: true, KeyDeployed: true}}
	jit := []byte("opaque-synthetic-jit")
	if err := g.StartRunner(context.Background(), lease, jit); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(commands.input, jit) {
		t.Fatal("JIT was not stdin")
	}
	for _, args := range commands.args {
		for _, arg := range args {
			if strings.Contains(arg, string(jit)) {
				t.Fatal("JIT in command arguments")
			}
		}
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("host staging file created for JIT")
	}
}

type cacheFallbackFixture struct {
	inputFixture
	removeFails bool
}

func (f *cacheFallbackFixture) Input(ctx context.Context, binary string, args []string, input []byte) ([]byte, error) {
	if slices.Contains(args, "cache-remove") && f.removeFails {
		return nil, errors.New("guest cleanup unavailable")
	}
	return f.inputFixture.Input(ctx, binary, args, input)
}
func TestCacheOutageRemovesPartialAdapterBeforeJIT(t *testing.T) {
	for _, removeFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean-fallback", true: "uncertain-cleanup"}[removeFails], func(t *testing.T) {
			_, _, _, record := engineFixture(t)
			dir := t.TempDir()
			commands := &cacheFallbackFixture{removeFails: removeFails}
			service, err := cache.Start(t.TempDir(), "127.0.0.1:0", "127.0.0.1", 1<<20, 1<<19, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			g := &SSHGuest{opts: GuestOptions{StateDir: dir, SSHBinary: "system-ssh", SSHKey: filepath.Join(dir, "missing-synthetic-key")}, commands: commands, cache: service}
			lease := Lease{Record: record, SSH: SSH{Host: "127.0.0.1", Port: 2222, User: "ciuser", State: 4, Enabled: true, KeyDeployed: true}}
			err = g.StartRunner(context.Background(), lease, []byte("opaque-synthetic-jit"))
			if removeFails {
				if err == nil || len(commands.args) != 0 {
					t.Fatal("uncertain cache cleanup admitted JIT")
				}
				return
			}
			if err != nil || len(commands.args) != 3 || !slices.Contains(commands.args[0], "cache-remove") || !slices.Contains(commands.args[1], "seed-jit") {
				t.Fatal("cache outage did not remove adapter before JIT")
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 0 {
				t.Fatal("cache capability staged on host")
			}
		})
	}
}

func TestWindowsGuestAdapterRefusesHostExecution(t *testing.T) {
	if err := RunWindowsGuest(context.Background(), "probe", os.Stdout); err == nil {
		t.Fatal("guest adapter ran on the host")
	}
}

func TestGuestForgetRemovesOnlyThatInstanceHostKey(t *testing.T) {
	_, _, _, record := engineFixture(t)
	dir := t.TempDir()
	g := &SSHGuest{opts: GuestOptions{StateDir: dir}}
	known := filepath.Join(dir, record.Meta.InstanceID+".known_hosts")
	other := filepath.Join(dir, "5678abcd.known_hosts")
	for _, path := range []string{known, other} {
		if err := os.WriteFile(path, []byte("synthetic host key"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := g.Forget(record.RunnerName); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(known); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted instance host key retained")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("another instance's host key removed")
	}
	if err := g.Forget("../escape"); err == nil {
		t.Fatal("unmanaged name accepted")
	}
}
