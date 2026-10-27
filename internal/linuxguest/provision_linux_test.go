//go:build linux

package linuxguest

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	linuxassets "github.com/GomerPiles/bivouac/tools/linux"
)

type provisionRecorder struct {
	calls   [][]string
	input   [][]byte
	respond func(string, []string, []byte) ([]byte, error)
}

func (r *provisionRecorder) Input(_ context.Context, binary string, args []string, input []byte) ([]byte, error) {
	r.calls = append(r.calls, append([]string{binary}, args...))
	r.input = append(r.input, append([]byte{}, input...))
	if r.respond != nil {
		return r.respond(binary, args, input)
	}
	return nil, nil
}
func (r *provisionRecorder) Run(ctx context.Context, binary string, args []string, out io.Writer) error {
	output, err := r.Input(ctx, binary, args, nil)
	if _, writeErr := out.Write(output); writeErr != nil {
		return writeErr
	}
	return err
}
func provisionFilesystemFixture(t *testing.T) (provisioner, *provisionRecorder, ProvisionRequest, []byte) {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = 1001, 1001
	}
	recorder := &provisionRecorder{}
	info, err := root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	p := provisioner{root: root, commands: recorder, ownerUID: info.Sys().(*syscall.Stat_t).Uid}
	for _, directory := range []string{"tmp", "etc/netplan", "root/.ssh", "home/bivouac/.ssh", "usr/bin", "etc/ssh", "sys/class/net/lo", "sys/class/net/ens3/device"} {
		if err := p.directory(directory); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.root.Symlink("../../../../bus/virtio/drivers/virtio_net", "sys/class/net/ens3/device/driver"); err != nil {
		t.Fatal(err)
	}
	archive, hash := runnerArchiveFixture(t)
	for name, data := range map[string][]byte{
		"etc/os-release": []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"),
		"etc/passwd":     []byte("root:x:0:0::/root:/bin/bash\nbivouac:x:" + strconv.Itoa(uid) + ":" + strconv.Itoa(gid) + "::/home/bivouac:/bin/bash\n"),
		"tmp/runner with spaces;$(literal).tar.gz": archive,
		"etc/netplan/50-cloud-init.yaml":           []byte("known installer layout"),
		"etc/resolv.conf":                          []byte("preparation resolver"),
		"usr/bin/cloud-init":                       []byte("fixture"),
		"root/.ssh/authorized_keys":                []byte("synthetic preparation authorization"),
		"home/bivouac/.bash_history":               []byte("synthetic preparation history"),
		"etc/ssh/ssh_host_ed25519_key":             []byte("synthetic preparation key"),
	} {
		if err := p.install(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	request := ProvisionRequest{Recipe: provisionRecipes()[0].name, RunnerArchive: "/tmp/runner with spaces;$(literal).tar.gz", RunnerSHA256: hash}
	helper := provisionHelperFixture()
	recorder.respond = func(binary string, args []string, input []byte) ([]byte, error) {
		if binary == "/usr/bin/cloud-init" && args[0] == "status" {
			return []byte(`{"status":"done"}`), nil
		}
		if binary == "/usr/bin/id" {
			return []byte("bivouac\n"), nil
		}
		if binary == "/usr/bin/systemctl" && args[0] == "show" {
			return []byte("loaded\n"), nil
		}
		if binary == "/usr/sbin/runuser" {
			var want GuestConfig
			if json.Unmarshal(input, &want) != nil || want.Profile != VZ {
				t.Fatal("bootstrap profile")
			}
			want.BootID = "12345678-1234-1234-1234-123456789abc"
			return json.Marshal(GuestPreparation{Config: want, DNSDHCP: true})
		}
		if binary == provisionStage {
			var request ImagePreparationRequest
			if json.Unmarshal(input, &request) != nil || request.Profile != VZ || len(request.BootID) != 36 {
				t.Fatal("image factory identity")
			}
			hash := sha256.Sum256(helper)
			if request.HelperSHA256 != hex.EncodeToString(hash[:]) {
				t.Fatal("image factory pin")
			}
			if err := p.install("usr/local/libexec/bivouac-guest", helper, 0755); err != nil {
				t.Fatal(err)
			}
			return json.Marshal(PreparedLinuxImage{Profile: VZ, DNSDHCP: true, HelperSHA256: request.HelperSHA256, RunnerUnconfigured: true, MachineIDCleared: true})
		}
		return nil, nil
	}
	return p, recorder, request, helper
}
func TestProvisionFilesystemAndFixedCommandFlow(t *testing.T) {
	p, r, request, helper := provisionFilesystemFixture(t)
	report, err := p.provision(context.Background(), request, helper)
	if err != nil || report.Profile != VZ || !report.DNSDHCP {
		t.Fatal("provision", err)
	}
	for name, want := range map[string][]byte{
		"usr/local/bin/bivouac": helper, "usr/local/libexec/bivouac-guest": helper,
		"etc/systemd/system/bivouac-guest-agent.service":               linuxassets.GuestAgentUnit(),
		"etc/systemd/system/bivouac-guest-agent.service.d/runner.conf": []byte(provisionAgentDropin),
		"etc/netplan/99-bivouac.yaml":                                  []byte(provisionNetwork),
	} {
		got, err := p.root.ReadFile(name)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("installed content", name, err)
		}
	}
	for _, name := range []string{"root/.ssh/authorized_keys", "home/bivouac/.bash_history", "etc/ssh/ssh_host_ed25519_key", "etc/netplan/50-cloud-init.yaml", strings.TrimPrefix(provisionStage, "/"), "usr/local/libexec/bivouac-provision"} {
		if _, err := p.root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("preparation artifact retained", name, err)
		}
	}
	if _, err := p.root.Stat("etc/cloud/cloud-init.disabled"); err != nil {
		t.Fatal(err)
	}
	if target, err := p.root.Readlink("etc/resolv.conf"); err != nil || target != "/run/systemd/resolve/stub-resolv.conf" {
		t.Fatal("DHCP stub resolver", err)
	}
	joined := []string{}
	for i, call := range r.calls {
		joined = append(joined, strings.Join(call, " "))
		if call[0] == "sh" || call[0] == "/bin/sh" || strings.Contains(strings.Join(call, " "), "sudoers") {
			t.Fatal("shell or sudo provisioning")
		}
		if len(r.input[i]) > 0 && call[0] != "/usr/sbin/runuser" && call[0] != provisionStage {
			t.Fatal("unexpected command input")
		}
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{"/usr/sbin/usermod --append --groups docker bivouac", "/usr/bin/systemctl disable ssh.service", "/usr/bin/systemctl disable ssh.socket", "/usr/bin/cloud-init clean --logs --seed", "/usr/sbin/netplan generate", provisionStage + " guest linux prepare-image"} {
		if !strings.Contains(all, want) {
			t.Fatal("missing recipe step", want)
		}
	}
	if strings.Contains(all, "netplan apply") || strings.Contains(all, " restart ") || strings.Contains(all, " stop ssh") {
		t.Fatal("preparation transport restarted")
	}
	if _, err := p.provision(context.Background(), request, helper); err == nil {
		t.Fatal("prepared image recapture accepted")
	}
}
func TestProvisionRefusesBeforeCommands(t *testing.T) {
	for _, kind := range []string{"digest", "archive-link", "network", "network-link", "account", "prepared", "runner", "unprotected-parent", "extra-nic", "non-virtio", "disabled-link", "disabled-writable"} {
		t.Run(kind, func(t *testing.T) {
			p, r, request, helper := provisionFilesystemFixture(t)
			switch kind {
			case "digest":
				request.RunnerSHA256 = strings.Repeat("0", 64)
			case "archive-link":
				if err := p.root.Rename(strings.TrimPrefix(request.RunnerArchive, "/"), "tmp/source"); err != nil {
					t.Fatal(err)
				}
				if err := p.root.Symlink("source", strings.TrimPrefix(request.RunnerArchive, "/")); err != nil {
					t.Fatal(err)
				}
			case "network":
				if err := p.install("etc/netplan/custom.yaml", nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "network-link":
				if err := p.root.Remove("etc/netplan/50-cloud-init.yaml"); err != nil {
					t.Fatal(err)
				}
				if err := p.root.Symlink("/etc/passwd", "etc/netplan/50-cloud-init.yaml"); err != nil {
					t.Fatal(err)
				}
			case "account":
				if err := p.root.WriteFile("etc/passwd", []byte("unknown:x:0:0::/root:/bin/sh\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "prepared":
				if err := p.install("etc/bivouac/prepared-image.json", nil, 0644); err != nil {
					t.Fatal(err)
				}
			case "runner":
				if err := p.directory("opt/actions-runner"); err != nil {
					t.Fatal(err)
				}
			case "extra-nic":
				if err := p.directory("sys/class/net/ens4"); err != nil {
					t.Fatal(err)
				}
			case "non-virtio":
				if err := p.root.Remove("sys/class/net/ens3/device/driver"); err != nil {
					t.Fatal(err)
				}
				if err := p.root.Symlink("../../other", "sys/class/net/ens3/device/driver"); err != nil {
					t.Fatal(err)
				}
			case "disabled-link":
				if err := p.directory("etc/cloud"); err != nil {
					t.Fatal(err)
				}
				if err := p.root.Symlink("/tmp/unknown", "etc/cloud/cloud-init.disabled"); err != nil {
					t.Fatal(err)
				}
			case "disabled-writable":
				if err := p.install("etc/cloud/cloud-init.disabled", nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := p.root.Chmod("etc/cloud/cloud-init.disabled", 0666); err != nil {
					t.Fatal(err)
				}
			case "unprotected-parent":
				if err := p.root.Chmod("etc/netplan", 0777); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := p.provision(context.Background(), request, helper); err == nil {
				t.Fatal("unsafe layout accepted")
			}
			if len(r.calls) != 0 {
				t.Fatal("commands ran before validation")
			}
		})
	}
}
func TestProvisionFactoryAndCommandFailureRefuseCapture(t *testing.T) {
	for _, kind := range []string{"command", "bootstrap-profile", "image-profile", "image-pin", "receipt"} {
		t.Run(kind, func(t *testing.T) {
			p, r, request, helper := provisionFilesystemFixture(t)
			original := r.respond
			r.respond = func(binary string, args []string, input []byte) ([]byte, error) {
				if kind == "command" {
					return nil, errors.New("synthetic failure")
				}
				output, err := original(binary, args, input)
				if err != nil {
					return output, err
				}
				if kind == "bootstrap-profile" && binary == "/usr/sbin/runuser" {
					return bytes.ReplaceAll(output, []byte(VZ), []byte(Crosvm)), nil
				}
				if binary == provisionStage {
					switch kind {
					case "image-profile":
						return bytes.ReplaceAll(output, []byte(VZ), []byte(Crosvm)), nil
					case "image-pin":
						var bad PreparedLinuxImage
						_ = json.Unmarshal(output, &bad)
						bad.HelperSHA256 = strings.Repeat("0", 64)
						return json.Marshal(bad)
					case "receipt":
						return []byte(`{"failed_stage":10}`), nil
					}
				}
				return output, nil
			}
			if _, err := p.provision(context.Background(), request, helper); err == nil {
				t.Fatal("failed recipe reported success")
			}
			for _, call := range r.calls {
				if call[0] == "/usr/sbin/runuser" && !reflect.DeepEqual(call, []string{"/usr/sbin/runuser", "-u", "bivouac", "--", provisionStage, "guest", "linux", "prepare"}) {
					t.Fatal("changed identity transport")
				}
			}
		})
	}
}
func TestProvisionInstallAndCleanupDoNotFollowLinks(t *testing.T) {
	p, _, _, _ := provisionFilesystemFixture(t)
	if err := p.install("usr/local/bin/test", []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.install("usr/local/bin/test", []byte("overwrite"), 0600); err == nil {
		t.Fatal("exclusive install overwritten")
	}
	if err := p.root.Symlink("bin", "usr/local/linked"); err != nil {
		t.Fatal(err)
	}
	if err := p.install("usr/local/linked/evil", nil, 0600); err == nil {
		t.Fatal("linked parent accepted")
	}
	if err := p.root.Remove("root/.ssh/authorized_keys"); err != nil {
		t.Fatal(err)
	}
	if err := p.root.Remove("root/.ssh"); err != nil {
		t.Fatal(err)
	}
	if err := p.root.Symlink("../home/bivouac", "root/.ssh"); err != nil {
		t.Fatal(err)
	}
	if err := p.removePreparationFile("root/.ssh/authorized_keys"); err == nil {
		t.Fatal("linked cleanup parent accepted")
	}
	data, err := p.root.ReadFile("usr/local/bin/test")
	if err != nil || string(data) != "sentinel" {
		t.Fatal("sentinel modified", err)
	}
}
func TestProvisionExtractionContainedLinks(t *testing.T) {
	p, _, _, _ := provisionFilesystemFixture(t)
	archive, hash := runnerArchiveFixture(t, &tar.Header{Name: "bin/safe", Typeflag: tar.TypeSymlink, Linkname: "Runner.Listener"}, &tar.Header{Name: "hard", Typeflag: tar.TypeLink, Linkname: "bin/Runner.Listener"})
	entries, err := planProvisionArchive(bytes.NewReader(archive), hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.extract(bytes.NewReader(archive), entries); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bin/safe", "hard"} {
		data, err := p.root.ReadFile(filepath.ToSlash("opt/actions-runner/" + name))
		if err != nil || string(data) != "fixture" {
			t.Fatal("safe archive link", err)
		}
	}
}

type provisionExitStatus int

func (s provisionExitStatus) Error() string { return "synthetic command exit" }
func (s provisionExitStatus) ExitCode() int { return int(s) }

func TestProvisionBulkOutputAndCloudCompletion(t *testing.T) {
	for _, kind := range []string{"bulk-output", "recoverable-done", "disabled", "degraded-large", "recoverable-running", "fatal-done", "oversize-status"} {
		t.Run(kind, func(t *testing.T) {
			p, r, request, helper := provisionFilesystemFixture(t)
			original := r.respond
			if kind == "disabled" {
				if err := p.install("etc/cloud/cloud-init.disabled", nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			r.respond = func(binary string, args []string, input []byte) ([]byte, error) {
				if kind == "bulk-output" && binary == "/usr/bin/env" {
					return bytes.Repeat([]byte("synthetic package progress\n"), 100000), nil
				}
				if binary == "/usr/bin/cloud-init" && args[0] == "status" {
					switch kind {
					case "recoverable-done":
						return []byte(`{"status":"done"}`), provisionExitStatus(2)
					case "disabled":
						return []byte(`{"status":"disabled"}`), nil
					case "degraded-large":
						return []byte(`{"status":"done","recoverable_errors":["` + strings.Repeat("x", 32000) + `"]}`), provisionExitStatus(2)
					case "recoverable-running":
						return []byte(`{"status":"running"}`), provisionExitStatus(2)
					case "fatal-done":
						return []byte(`{"status":"done"}`), provisionExitStatus(1)
					case "oversize-status":
						return bytes.Repeat([]byte(" "), provisionCloudStatusLimit+1), nil
					}
				}
				return original(binary, args, input)
			}
			_, err := p.provision(context.Background(), request, helper)
			valid := kind == "bulk-output" || kind == "recoverable-done" || kind == "disabled" || kind == "degraded-large"
			if (err == nil) != valid {
				t.Fatal("bulk/status result differs", err)
			}
			if !valid {
				for _, call := range r.calls {
					if call[0] != "/usr/bin/cloud-init" || call[1] != "status" {
						t.Fatal("cloud-init refusal followed image mutation", call)
					}
				}
				for _, name := range []string{"opt/actions-runner", "usr/local/bin/bivouac", "etc/cloud/cloud-init.disabled"} {
					if _, err := p.root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
						t.Fatal("cloud-init refusal changed filesystem", name, err)
					}
				}
				if data, err := p.root.ReadFile("root/.ssh/authorized_keys"); err != nil || len(data) == 0 {
					t.Fatal("cloud-init refusal removed preparation authorization", err)
				}
				var failure *provisionFailure
				if !errors.As(err, &failure) || failure.Stage != 6 {
					t.Fatal("unclassified preflight failure", err)
				}
			}
		})
	}
}
func TestProvisionReportsOnlyNumericFailureStage(t *testing.T) {
	var output bytes.Buffer
	err := provisionLinux(context.Background(), strings.NewReader(`{"recipe":"synthetic-private-request"}`), &output)
	if err == nil || err.Error() != "linux provisioning refused at stage 1" || output.String() != "{\"failed_stage\":1}\n" {
		t.Fatal("unbounded or missing failure receipt", err)
	}
	p, r, request, helper := provisionFilesystemFixture(t)
	original := r.respond
	r.respond = func(binary string, args []string, input []byte) ([]byte, error) {
		if binary == "/usr/bin/cloud-init" {
			return original(binary, args, input)
		}
		return nil, errors.New("synthetic-private-command-output")
	}
	_, err = p.provision(context.Background(), request, helper)
	if err == nil || err.Error() != "linux provisioning refused at stage 7" {
		t.Fatal("package failure missing its fixed stage", err)
	}
}
func TestProvisionNativeBulkOutput(t *testing.T) {
	if os.Args[len(os.Args)-1] == "provision-bulk-output-fixture" {
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("synthetic package progress\n"), 100000))
		os.Exit(0)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := provisioner{commands: nativeProvisionCommands{}}
	if err := p.discard(context.Background(), exe, []string{"-test.run=^TestProvisionNativeBulkOutput$", "--", "provision-bulk-output-fixture"}); err != nil {
		t.Fatal("unused stdout volume refused a successful command", err)
	}
}
