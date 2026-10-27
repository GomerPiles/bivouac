//go:build linux

package linuxguest

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/provider"
)

func TestPersistedConfigurationBindsProfileAndCurrentBoot(t *testing.T) {
	boot, err := bootIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	for _, profile := range []ExecutionProfile{Crosvm, VZ, "", "unknown"} {
		cfg := GuestConfig{Profile: profile, Name: "bivouac-linux-1234abcd", ControllerID: "controller", RunnerDir: "/opt/actions-runner", BootID: boot}
		b, _ := json.Marshal(cfg)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readGuestConfig(path)
		if profile.Validate() != nil {
			if err == nil {
				t.Fatal("persisted invalid profile admitted")
			}
			continue
		}
		if err != nil || got != cfg {
			t.Fatal("persisted profile lost", err)
		}
		for _, invalid := range [][]byte{[]byte(strings.Replace(string(b), boot, "stale-boot", 1)), append(b, []byte(" {}")...), []byte(strings.Replace(string(b), "{", `{"unknown":true,`, 1)), make([]byte, 65537)} {
			if err := os.WriteFile(path, invalid, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readGuestConfig(path); err == nil {
				t.Fatal("unbounded, unknown or stale configuration admitted")
			}
		}
	}
}

// This runs a harmless local process, never a guest or official runner. The
// same /proc identity checks guard status and cancellation in the guest.
func TestNativeListenerStatusAndCancellation(t *testing.T) {
	root := t.TempDir()
	runner := filepath.Join(root, "runner")
	if err := os.MkdirAll(filepath.Join(runner, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(runner, "bin", "Runner.Listener")
	// #nosec G306 -- This private, short-lived native process fixture must be executable.
	if err := os.WriteFile(image, binary, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := GuestConfig{Profile: VZ, RunnerDir: runner}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, image, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	identity, live, err := process(cmd.Process.Pid)
	if err != nil || !live || identity.Image != image {
		t.Fatal("native listener identity failed", err)
	}
	write := func(name string, value any) {
		t.Helper()
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(root, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("listener.json", identity)
	if err := os.WriteFile(filepath.Join(root, "runner.log"), []byte("Listening for Jobs"), 0600); err != nil {
		t.Fatal(err)
	}
	status, err := linuxStatus(root, cfg)
	if err != nil || status.State != provider.RunnerListening {
		t.Fatal("listening state lost", err)
	}
	write("job.json", provider.RunnerJob{RunID: 42})
	status, err = linuxStatus(root, cfg)
	if err != nil || status.State != provider.RunnerRunning || status.Job.RunID != 42 {
		t.Fatal("running state lost", err)
	}
	bad := identity
	bad.Start = "reused-pid"
	write("listener.json", bad)
	if _, err := linuxStatus(root, cfg); err == nil {
		t.Fatal("reused PID admitted by status")
	}
	if err := cancelListener(root, cfg); err == nil {
		t.Fatal("reused PID admitted by cancel")
	}
	if _, live, err := process(cmd.Process.Pid); err != nil || !live {
		t.Fatal("unproven listener was stopped")
	}
	write("listener.json", identity)
	if err := cancelListener(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("listener did not receive termination")
	}
	write("runner.exit", struct{ Code int }{17})
	status, err = linuxStatus(root, cfg)
	if err != nil || status.State != provider.RunnerExited || status.ExitCode != 17 {
		t.Fatal("exit status lost", err)
	}
}

type unitCommands struct {
	noCommands
	calls int
}

func (c *unitCommands) Output(_ context.Context, binary string, args []string) ([]byte, error) {
	if binary != "/usr/bin/systemctl" || !reflect.DeepEqual(args, []string{"daemon-reload"}) {
		return nil, errors.New("unexpected sanitation command")
	}
	c.calls++
	return nil, nil
}

func TestProfileSanitationWritesOnlySSHUnits(t *testing.T) {
	for _, profile := range []ExecutionProfile{Crosvm, VZ} {
		root := t.TempDir()
		commands := &unitCommands{}
		var paths []string
		write := func(path string, data []byte, mode os.FileMode) error {
			paths = append(paths, path)
			return os.WriteFile(filepath.Join(root, filepath.Base(path)), data, mode)
		}
		if err := installImageUnits(context.Background(), profile, commands, write); err != nil {
			t.Fatal(err)
		}
		if profile == VZ {
			if len(paths) != 0 || commands.calls != 0 || len(imageIdentityFiles(profile)) != 1 {
				t.Fatal("VZ acquired SSH sanitation")
			}
			continue
		}
		if !reflect.DeepEqual(paths, []string{"/etc/systemd/system/bivouac-ssh-hostkeys.service", "/etc/systemd/system/ssh.service.d/bivouac-hostkeys.conf"}) || commands.calls != 1 || len(imageIdentityFiles(profile)) != 7 {
			t.Fatal("Crosvm SSH sanitation changed")
		}
		for name, expected := range map[string]string{"bivouac-ssh-hostkeys.service": sshHostKeyUnit, "bivouac-hostkeys.conf": sshHostKeyDependency} {
			b, err := os.ReadFile(filepath.Join(root, name))
			if err != nil || string(b) != expected {
				t.Fatal("wrong SSH unit content", err)
			}
		}
	}
}

func TestPreparedMarkerBindsRunningHelper(t *testing.T) {
	hash, err := HelperSHA256("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []ExecutionProfile{Crosvm, VZ} {
		report := PreparedLinuxImage{Profile: profile, HelperSHA256: hash, RunnerUnconfigured: true, MachineIDCleared: true, DNSPrepared: profile == Crosvm, DNSDHCP: profile == VZ, SSHHostKeysRemoved: profile == Crosvm}
		data, _ := json.Marshal(report)
		if err := validateRunningPreparedProfile(data, profile); err != nil {
			t.Fatal("matching running helper refused", err)
		}
		report.HelperSHA256 = strings.Repeat("0", 64)
		data, _ = json.Marshal(report)
		if err := validateRunningPreparedProfile(data, profile); err == nil {
			t.Fatal("stale helper marker accepted")
		}
	}
}
