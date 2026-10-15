package tart

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider"
)

// recorder is a fake tart binary: it records argument arrays and answers
// from a table.
type recorder struct {
	calls     [][]string
	stdin     map[string]string // joined args -> stdin received
	vms       map[string]bool   // name -> running
	exited    map[string]bool
	status    string
	statusErr error // returned by `exec ... status` when set
	session   string
	diag      map[string][]byte // guest script mode -> stdout
	launchOut string            // written by `tart run` instead of "started"
	started   []*fakeProc
}

type fakeProc struct {
	done chan struct{}
	args []string
}

func (f *fakeProc) PID() int              { return 4242 }
func (f *fakeProc) Done() <-chan struct{} { return f.done }
func (f *fakeProc) Err() error            { return nil }
func (f *fakeProc) Kill() error {
	select {
	case <-f.done:
	default:
		close(f.done)
	}
	return nil
}

func newRecorder() *recorder {
	return &recorder{stdin: map[string]string{}, vms: map[string]bool{"base": false}, exited: map[string]bool{}, status: "listening", session: "Aqua", diag: map[string][]byte{}}
}

func (r *recorder) Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	out, err := r.answer(ctx, args, stdin)
	if len(out) > 0 {
		if _, werr := stdout.Write(out); werr != nil {
			return &Error{Args: args, Err: werr}
		}
	}
	return err
}

func (r *recorder) answer(_ context.Context, args []string, stdin io.Reader) ([]byte, error) {
	r.calls = append(r.calls, args)
	if stdin != nil {
		b, _ := io.ReadAll(stdin)
		r.stdin[strings.Join(args, " ")] = string(b)
	}
	switch args[0] {
	case "clone":
		if _, ok := r.vms[args[1]]; !ok {
			return nil, &Error{Args: args, Stderr: "VM does not exist"}
		}
		r.vms[args[2]] = false
		return nil, nil
	case "list":
		var out []listEntry
		for n, running := range r.vms {
			out = append(out, listEntry{Name: n, Source: "local", Running: running})
		}
		return json.Marshal(out)
	case "delete":
		if _, ok := r.vms[args[1]]; !ok {
			return nil, &Error{Args: args, Stderr: "not found"}
		}
		delete(r.vms, args[1])
		return nil, nil
	case "stop":
		r.vms[args[1]] = false
		for _, p := range r.started {
			if p.args[len(p.args)-1] == args[1] {
				_ = p.Kill()
			}
		}
		return nil, nil
	case "exec":
		i := 1
		if args[1] == "-i" {
			i = 2
		}
		if len(args) > i+2 && args[i+1] == guestPath {
			switch args[i+2] {
			case "status":
				if r.statusErr != nil {
					return nil, r.statusErr
				}
				return []byte(r.status + "\n"), nil
			case "session":
				return []byte(r.session + "\n"), nil
			case "start":
				return []byte("started\n"), nil
			case "diag", "diag-runner":
				return r.diag[args[i+2]], nil
			}
		}
		return nil, nil
	}
	return nil, nil
}

func (r *recorder) Start(_ context.Context, args []string, sink io.Writer) (Process, error) {
	r.calls = append(r.calls, args)
	r.vms[args[len(args)-1]] = true
	out := "started\n"
	if r.launchOut != "" {
		out = r.launchOut
	}
	_, _ = sink.Write([]byte(out))
	p := &fakeProc{done: make(chan struct{}), args: args}
	r.started = append(r.started, p)
	return p, nil
}

func newProvider(t *testing.T, r *recorder) *Provider {
	t.Helper()
	home := t.TempDir()
	t.Setenv("TART_HOME", home)
	for name := range r.vms {
		if err := os.MkdirAll(filepath.Join(home, "vms", name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Tart{Baseline: "base", CPU: 4, MemoryGB: 8, ExtraArgs: []string{"--no-audio"}, RunnerDir: "/Users/admin/actions-runner", HostVMLimit: 2}
	p, err := New("macos", cfg, "ctl-1", r)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLifecycleArguments(t *testing.T) {
	r := newRecorder()
	p := newProvider(t, r)
	home := os.Getenv("TART_HOME")
	ctx := context.Background()
	spec := provider.Spec{Name: "bivouac-macos-abc", Baseline: "base", CPU: 4, MemoryMB: 8192, Launch: provider.Launch{Args: []string{"--no-audio"}}, Meta: provider.Metadata{ControllerID: "ctl-1", InstanceID: "abc"}}
	// Simulate tart clone creating the directory before the marker is written.
	if err := os.MkdirAll(filepath.Join(home, "vms", spec.Name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := p.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"clone", "base", "bivouac-macos-abc"}, {"set", "bivouac-macos-abc", "--cpu", "4", "--memory", "8192"}}
	for i, w := range want {
		if strings.Join(r.calls[i], " ") != strings.Join(w, " ") {
			t.Fatalf("call %d = %v, want %v", i, r.calls[i], w)
		}
	}
	var sink strings.Builder
	if err := p.Start(ctx, spec.Name, &sink); err != nil {
		t.Fatal(err)
	}
	run := r.calls[len(r.calls)-1]
	if got := strings.Join(run, " "); got != "run --no-graphics --no-audio bivouac-macos-abc" {
		t.Fatalf("run args = %q", got)
	}
	if err := p.WaitReady(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	if got := r.stdin["exec -i bivouac-macos-abc tee /tmp/bivouac-guest"]; !strings.Contains(got, "ACTIONS_RUNNER_INPUT_JITCONFIG") {
		t.Fatalf("guest script not delivered: %q", got)
	}
	if err := p.StartRunner(ctx, spec.Name, []byte("secret-jit")); err != nil {
		t.Fatal(err)
	}
	if got := r.stdin["exec -i bivouac-macos-abc /tmp/bivouac-guest start /Users/admin/actions-runner"]; got != "secret-jit" {
		t.Fatalf("JIT not delivered on stdin: %q", got)
	}
	for _, c := range r.calls {
		for _, a := range c {
			if strings.Contains(a, "secret-jit") {
				t.Fatalf("JIT config on a command line: %v", c)
			}
		}
	}
	st, err := p.RunnerStatus(ctx, spec.Name)
	if err != nil || st.State != provider.RunnerListening {
		t.Fatalf("status = %+v, %v", st, err)
	}
	r.status = "exited 0"
	st, _ = p.RunnerStatus(ctx, spec.Name)
	if st.State != provider.RunnerExited || st.ExitCode != 0 {
		t.Fatalf("status = %+v", st)
	}
	if err := p.Stop(ctx, spec.Name, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.vms[spec.Name]; ok {
		t.Fatal("vm not deleted")
	}
}

func TestDeleteRefusesBaselineAndForeign(t *testing.T) {
	r := newRecorder()
	r.vms["bivouac-macos-other"] = false
	r.vms["tartelet-clone-1"] = true
	p := newProvider(t, r)
	ctx := context.Background()
	home := os.Getenv("TART_HOME")
	// A prefixed VM with another controller's marker.
	_ = os.WriteFile(filepath.Join(home, "vms", "bivouac-macos-other", markerFile), []byte(`{"controller_id":"someone-else"}`), 0o600)

	for _, name := range []string{"base", "tartelet-clone-1", "bivouac-macos-other", "bivouac-macos-missing"} {
		err := p.Delete(ctx, name)
		if err == nil {
			t.Fatalf("delete %s succeeded", name)
		}
		if name != "bivouac-macos-missing" && !errors.Is(err, provider.ErrNotOwned) {
			t.Fatalf("delete %s: %v, want ErrNotOwned", name, err)
		}
	}
	for _, c := range r.calls {
		if c[0] == "delete" {
			t.Fatalf("tart delete was invoked: %v", c)
		}
	}
	owned, foreign, err := p.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 0 {
		t.Fatalf("owned = %v", owned)
	}
	var names []string
	for _, f := range foreign {
		names = append(names, f.Name)
		if f.Name == "bivouac-macos-other" && !f.Prefixed {
			t.Fatal("prefixed foreign VM not flagged")
		}
	}
	if len(names) != 2 {
		t.Fatalf("foreign = %v", names)
	}
}

func TestRunnerJobIdentity(t *testing.T) {
	for _, phase := range []string{"running", "exited 0"} {
		st, _ := parseRunnerStatus(phase + "\nrun_id=123\nrepository=example-org/repo\njob=macos\n")
		if st.Job == nil || st.Job.RunID != 123 || st.Job.Name != "macos" || st.Job.Repository != "example-org/repo" {
			t.Fatalf("missing identity: %+v", st)
		}
	}
	for _, metadata := range []string{"run_id=bad\nrepository=example-org/repo", "run_id=123\nrepository=example-org/repo/extra", "run_id=123"} {
		if st, _ := parseRunnerStatus("listening\n" + metadata); st.Job != nil {
			t.Fatalf("accepted malformed identity: %+v", st.Job)
		}
	}
}
