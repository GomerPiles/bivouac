package vm

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func baselineHome(t *testing.T) Home {
	t.Helper()
	home := Home(t.TempDir())
	dir := home.Dir("base")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{ConfigFile: tartConfig, DiskFile: "disk", NVRAMFile: "nvram"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func TestCloneResizeListDelete(t *testing.T) {
	home := baselineHome(t)
	if err := home.Clone("base", "bivouac-a"); err != nil {
		t.Fatal(err)
	}
	base, _ := ReadConfig(home.Dir("base"))
	clone, err := ReadConfig(home.Dir("bivouac-a"))
	if err != nil {
		t.Fatal(err)
	}
	if clone.MACAddress == base.MACAddress {
		t.Fatal("clone kept the baseline MAC address")
	}
	if data, _ := os.ReadFile(filepath.Join(home.Dir("bivouac-a"), DiskFile)); string(data) != "disk" {
		t.Fatal("disk not cloned")
	}
	if err := home.Clone("base", "bivouac-a"); err == nil {
		t.Fatal("clone replaced an existing VM")
	}
	if err := home.Resize("bivouac-a", 1, 0); err == nil {
		t.Fatal("resize went below cpuCountMin")
	}
	if err := home.Resize("bivouac-a", 8, 16384); err != nil {
		t.Fatal(err)
	}
	if c, _ := ReadConfig(home.Dir("bivouac-a")); c.CPUCount != 8 || c.MemorySize != 16<<30 {
		t.Fatalf("resized to %d CPUs, %d bytes", c.CPUCount, c.MemorySize)
	}
	// A crashed clone leaves only a hidden staging directory, never listed.
	if err := os.Mkdir(filepath.Join(string(home), "vms", ".bivouac-b.clone"), 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := home.List()
	if err != nil || len(entries) != 2 || entries[0].Running || entries[1].Running {
		t.Fatalf("list = %+v, %v", entries, err)
	}
	if err := home.Delete("bivouac-a"); err != nil {
		t.Fatal(err)
	}
	if err := home.Delete("bivouac-a"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestLockMatchesTartRunningState(t *testing.T) {
	if os.Getenv("BIVOUAC_TEST_HOLD_LOCK") != "" {
		holdLock(t)
		return
	}
	home := baselineHome(t)
	dir := home.Dir("base")
	// fcntl locks are per process, so the holder is a child.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestLockMatchesTartRunningState$")
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
	if err := home.Resize("base", 4, 0); err == nil {
		t.Fatal("resized a running VM")
	}
	if err := home.Clone("base", "bivouac-copy"); err == nil {
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
	opts := RunOptions{Dir: "/vms/x", AgentPort: 1}
	helper := append([]string{"/opt/bivouac", "vm", "run"}, opts.Args()...)
	if !isHelper(helper, "/vms/x") || isHelper(helper, "/vms/y") || isHelper([]string{"tart", "run", "x"}, "/vms/x") {
		t.Fatal("helper argument match is wrong")
	}
}
