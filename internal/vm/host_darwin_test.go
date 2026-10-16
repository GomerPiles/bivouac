package vm

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
)

func baselineStore(t *testing.T) Store {
	t.Helper()
	// Test names make t.TempDir too long for socket paths.
	root, err := os.MkdirTemp("", "vm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	home := Store(root)
	tart := t.TempDir()
	for name, body := range map[string]string{tartConfigFile: tartFixture, DiskFile: "disk", NVRAMFile: "nvram"} {
		if err := os.WriteFile(filepath.Join(tart, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := home.Import(tart, "base", testManifest().Guest); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestImportCloneListDelete(t *testing.T) {
	home := baselineStore(t)
	if m, err := ReadManifest(home.Dir("base")); err != nil || !reflect.DeepEqual(m, testManifest()) {
		t.Fatalf("imported %+v, %v", m, err)
	}
	if _, err := os.Lstat(filepath.Join(home.Dir("base"), tartConfigFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("import kept Tart's config.json")
	}
	if err := home.Clone("base", "bivouac-a", CloneOptions{CPU: 1}); err == nil {
		t.Fatal("clone went below the minimum CPU count")
	}
	if err := home.Clone("base", "bivouac-a", CloneOptions{MemoryMiB: 1024}); err == nil {
		t.Fatal("clone went below the minimum memory")
	}
	if err := home.Clone("base", "bivouac-a", CloneOptions{CPU: 8, MemoryMiB: 16384}); err != nil {
		t.Fatal(err)
	}
	clone, err := ReadManifest(home.Dir("bivouac-a"))
	if err != nil {
		t.Fatal(err)
	}
	if clone.MAC == testManifest().MAC || clone.CPU != 8 || clone.MemoryMiB != 16384 || clone.Guest != testManifest().Guest {
		t.Fatalf("clone manifest %+v", clone)
	}
	if data, _ := os.ReadFile(filepath.Join(home.Dir("bivouac-a"), DiskFile)); string(data) != "disk" {
		t.Fatal("disk not cloned")
	}
	if err := home.Clone("base", "bivouac-a", CloneOptions{}); err == nil {
		t.Fatal("clone replaced an existing VM")
	}
	// A directory without a manifest is not a baseline.
	if err := os.Mkdir(home.Dir("tart-only"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := home.Clone("tart-only", "bivouac-b", CloneOptions{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("cloned a directory without a manifest: %v", err)
	}
	if err := os.Remove(home.Dir("tart-only")); err != nil {
		t.Fatal(err)
	}
	// A crashed clone leaves only a hidden staging directory, and the socket
	// directory is hidden too; neither is listed.
	if err := os.Mkdir(filepath.Join(string(home), ".bivouac-b.clone"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(string(home), runDir), 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := home.List()
	if err != nil || len(entries) != 2 || entries[0].Running || entries[1].Running {
		t.Fatalf("list = %+v, %v", entries, err)
	}
	// A VM whose lock cannot be read counts as running and hides no other.
	unreadable := filepath.Join(home.Dir("base"), ManifestFile)
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	entries, err = home.List()
	_ = os.Chmod(unreadable, 0o600)
	if err != nil || len(entries) != 2 || !entries[0].Running || entries[0].Name != "base" || entries[1].Running {
		t.Fatalf("list with an unreadable VM = %+v, %v", entries, err)
	}
	// A killed helper's socket goes with its VM.
	stale, err := home.SocketPath("bivouac-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := home.Delete("bivouac-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stale socket kept: %v", err)
	}
	if err := home.Delete("bivouac-a"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestLockMarksTheVMRunning(t *testing.T) {
	if os.Getenv("BIVOUAC_TEST_HOLD_LOCK") != "" {
		holdLock(t)
		return
	}
	home := baselineStore(t)
	dir := home.Dir("base")
	// fcntl locks are per process, so the holder is a child.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestLockMarksTheVMRunning$")
	cmd.Env = append(os.Environ(), "BIVOUAC_TEST_HOLD_LOCK="+dir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		pid, err := Holder(dir)
		if err != nil {
			t.Fatal(err)
		}
		if pid == cmd.Process.Pid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("holder = %d, want %d", pid, cmd.Process.Pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := Acquire(dir); err == nil {
		t.Fatal("acquired a held lock")
	}
	if err := home.Delete("base"); err == nil {
		t.Fatal("deleted a running VM")
	}
	if err := home.Clone("base", "bivouac-copy", CloneOptions{}); err == nil {
		t.Fatal("cloned a running baseline")
	}
	// The holder is a test binary, not `bivouac vm run --dir <dir>`.
	if _, err := HelperPID(dir); !errors.Is(err, ErrForeignHolder) {
		t.Fatalf("HelperPID = %v, want ErrForeignHolder", err)
	}
	if entries, _ := home.List(); len(entries) != 1 || !entries[0].Running {
		t.Fatalf("list = %+v", entries)
	}
	_ = stdin.Close()
	_ = cmd.Wait()
	if pid, err := Holder(dir); err != nil || pid != 0 {
		t.Fatalf("holder after exit = %d, %v", pid, err)
	}
}

func holdLock(t *testing.T) {
	lock, err := Acquire(os.Getenv("BIVOUAC_TEST_HOLD_LOCK"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()
	_, _ = os.Stdin.Read(make([]byte, 1))
}

func TestProcessArgsIdentifyHelpers(t *testing.T) {
	args, err := processArgs(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(args, os.Args) {
		t.Fatalf("processArgs = %q, want %q", args, os.Args)
	}
	opts := RunOptions{Dir: "/vms/x", AgentPort: 1, AgentSocket: "/vms/.run/x.sock"}
	helper := append([]string{"/opt/bivouac", "vm", "run"}, opts.Args()...)
	if !isHelper(helper, "/vms/x") || isHelper(helper, "/vms/y") || isHelper([]string{"othervm", "run", "x"}, "/vms/x") {
		t.Fatal("helper argument match is wrong")
	}
}
