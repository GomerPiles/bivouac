package tart

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/perf"
)

// Exercise the wrapper's real child process and recorder together, including
// an official-listener failure. The fixture never registers or launches a VM.
func TestGuestWrapperOwnsSamplerAndPreservesListenerExit(t *testing.T) {
	directory, runner := t.TempDir(), filepath.Join(t.TempDir(), "runner with spaces")
	if err := os.MkdirAll(filepath.Join(runner, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	listener := filepath.Join(runner, "bin", "Runner.Listener")
	fixture := "#!/bin/sh\nwhile [ ! -f \"$BIVOUAC_TEST_DIRECTORY/finish\" ]; do sleep 0.05; done\nexit 7\n"
	if err := os.WriteFile(listener, []byte(fixture), 0o700); err != nil { // #nosec G306 -- Executable synthetic listener fixture in t.TempDir().
		t.Fatal(err)
	}
	t.Setenv("BIVOUAC_TEST_DIRECTORY", directory)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runGuest(ctx, "run", directory, runner, &bytes.Buffer{}) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, _ := os.ReadFile(filepath.Join(directory, "listener.pid"))
		pid, _ := strconv.Atoi(string(data))
		if pid > 0 && syscall.Kill(pid, 0) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener identity unavailable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(directory, perf.FileName)); !os.IsNotExist(err) {
		t.Fatal("idle listener generated a job report")
	}
	var output bytes.Buffer
	if err := runGuest(ctx, "hook", directory, runner, &output); err != nil {
		t.Fatal(err)
	}
	if err := runGuest(ctx, "hook-completed", directory, runner, &output); err != nil {
		t.Fatal(err)
	}
	report, err := perf.ReadReport(directory)
	if err != nil || !report.Complete || !strings.Contains(output.String(), "final_sample=true") {
		t.Fatal("guest hooks did not flush numeric telemetry", report, err, output.String())
	}
	if err := os.WriteFile(filepath.Join(directory, "finish"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err = <-done
	// Put the result back for the deferred join.
	done <- err
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 {
		t.Fatal("wrapper lost official runner exit", err)
	}
	before, _ := os.ReadFile(filepath.Join(directory, perf.FileName))
	time.Sleep(50 * time.Millisecond)
	after, _ := os.ReadFile(filepath.Join(directory, perf.FileName))
	if !bytes.Equal(before, after) {
		t.Fatal("recorder outlived listener")
	}
}

func TestShellBootstrapHooksAndWrapper(t *testing.T) {
	root := t.TempDir()
	runner := filepath.Join(root, "runner with spaces")
	if err := os.MkdirAll(filepath.Join(runner, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Rewrite only the fixed guest root to keep this executable fixture entirely
	// in t.TempDir(). No host manager, VM or baseline is involved.
	script := strings.ReplaceAll(string(guestScript), "/tmp/bivouac", filepath.Join(root, "bivouac"))
	helper := `#!/bin/sh
case "$3" in
run)
  "$4/bin/Runner.Listener" run &
  listener=$!
  echo "$listener" > "$BIVOUAC_TEST_ROOT/bivouac/listener.pid"
  wait "$listener"
  exit $?
  ;;
hook) echo '[bivouac performance] start: fixture';;
hook-completed)
  echo '[bivouac performance] finish: fixture'
  echo '[bivouac cache] archives: hits=1 misses=1; release proxy: hits=1'
  ;;
*) exit 64;;
esac
`
	listener := `#!/bin/sh
[ "$ACTIONS_RUNNER_INPUT_JITCONFIG" = synthetic-jit ] || exit 9
[ "$BIVOUAC_RUNNER_DIRECTORY" = "$PWD" ] || exit 10
echo 'Listening for Jobs'
"$ACTIONS_RUNNER_HOOK_JOB_STARTED" || exit 11
"$ACTIONS_RUNNER_HOOK_JOB_COMPLETED" || exit 12
exit 7
`
	for path, data := range map[string]string{
		filepath.Join(root, "guest.sh"):                 script,
		filepath.Join(root, "bivouac-helper"):           helper,
		filepath.Join(runner, "bin", "Runner.Listener"): listener,
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o700); err != nil { // #nosec G302 -- Executable synthetic guest fixtures in t.TempDir().
			t.Fatal(err)
		}
	}
	t.Setenv("BIVOUAC_TEST_ROOT", root)
	t.Setenv("GITHUB_RUN_ID", "123")
	t.Setenv("GITHUB_REPOSITORY", "example/repository")
	t.Setenv("GITHUB_JOB", "macos")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", filepath.Join(root, "guest.sh"), "start", runner)
	cmd.Stdin = strings.NewReader("synthetic-jit")
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "started\n" {
		t.Fatal(string(out), err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		exit, err := os.ReadFile(filepath.Join(root, "bivouac", "runner.exit"))
		if err == nil {
			if string(exit) != "7\n" {
				t.Fatal("bootstrap lost listener result", string(exit))
			}
			break
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(filepath.Join(root, "bivouac", "runner.log"))
			t.Fatal("bootstrap never finished:", string(log))
		}
		time.Sleep(10 * time.Millisecond)
	}
	log, err := os.ReadFile(filepath.Join(root, "bivouac", "runner.log"))
	if err != nil || !strings.Contains(string(log), "[bivouac performance] start:") || !strings.Contains(string(log), "[bivouac performance] finish:") || !strings.Contains(string(log), "[bivouac cache]") || strings.Contains(string(log), "synthetic-jit") {
		t.Fatal("hooks missing or private input leaked", err)
	}
	job, err := os.ReadFile(filepath.Join(root, "bivouac", "job"))
	if err != nil || string(job) != "run_id=123\nrepository=example/repository\njob=macos\n" {
		t.Fatal("job identity changed", err)
	}
}

type failedHelper struct {
	*recorder
	cleanupFails bool
}

func (f failedHelper) Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if strings.Contains(strings.Join(args, " "), "dd of="+guestHelper) {
		return errors.New("synthetic partial copy failure")
	}
	if f.cleanupFails && len(args) >= 3 && args[len(args)-1] == guestHelper && args[len(args)-3] == "rm" {
		return errors.New("synthetic cleanup failure")
	}
	return f.recorder.Run(ctx, args, stdin, stdout)
}

func TestPartialHelperInstallationFallsBackOnlyAfterRemoval(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		r := newRecorder()
		p := newProvider(t, r)
		writeMarker(t, p, "bivouac-macos-fixture")
		p.rt = argvRuntime{failedHelper{r, cleanupFails}}
		err := p.StartRunner(context.Background(), "bivouac-macos-fixture", []byte("synthetic-jit"))
		if (err != nil) != cleanupFails {
			t.Fatal("partial helper cleanup outcome", err)
		}
		started := false
		for _, call := range r.calls {
			if strings.Contains(strings.Join(call, " "), guestPath+" start") {
				started = true
			}
		}
		if started == cleanupFails {
			t.Fatal("JIT dispatched before partial helper removal")
		}
	}
}
