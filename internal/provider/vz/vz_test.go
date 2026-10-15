package vz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/vm"
)

// callRecorder records each Runtime call as a verb and its arguments;
// callRuntime adapts it to Runtime so assertions and fault injection read as
// one line per call.
type callRecorder interface {
	Run(ctx context.Context, call []string, stdin io.Reader, stdout io.Writer) error
	Start(ctx context.Context, call []string, sink io.Writer) (Process, error)
}

type callRuntime struct{ calls callRecorder }

func (c callRuntime) Clone(ctx context.Context, baseline, name string) error {
	return c.calls.Run(ctx, []string{"Clone", baseline, name}, nil, io.Discard)
}

func (c callRuntime) Resize(ctx context.Context, name string, cpu, memoryMB int) error {
	return c.calls.Run(ctx, []string{"Resize", name, "cpu=" + strconv.Itoa(cpu), "memory=" + strconv.Itoa(memoryMB)}, nil, io.Discard)
}

// Start records the VM name last.
func (c callRuntime) Start(ctx context.Context, name string, launch Launch, sink io.Writer) (Process, error) {
	call := []string{"Start"}
	if launch.Input {
		call = append(call, "input")
	}
	if launch.Share != "" {
		call = append(call, "share="+launch.Share)
	}
	if launch.Softnet != nil {
		call = append(call, "softnet-block="+launch.Softnet.Block)
	}
	return c.calls.Start(ctx, append(call, name), sink)
}

func (c callRuntime) Exec(ctx context.Context, name string, argv []string, stdin io.Reader, stdout io.Writer) error {
	return c.calls.Run(ctx, append([]string{"Exec", name}, argv...), stdin, stdout)
}

func (c callRuntime) Duplex(ctx context.Context, name string, argv []string) (net.Conn, error) {
	return nil, c.calls.Run(ctx, append([]string{"Duplex", name}, argv...), nil, io.Discard)
}

func (c callRuntime) Stop(ctx context.Context, name string, timeout time.Duration) error {
	return c.calls.Run(ctx, []string{"Stop", name, "timeout=" + timeout.String()}, nil, io.Discard)
}

func (c callRuntime) Delete(ctx context.Context, name string) error {
	return c.calls.Run(ctx, []string{"Delete", name}, nil, io.Discard)
}

func (c callRuntime) List(ctx context.Context) ([]vm.Entry, error) {
	var out bytes.Buffer
	if err := c.calls.Run(ctx, []string{"List"}, nil, &out); err != nil {
		return nil, err
	}
	var entries []vm.Entry
	return entries, json.Unmarshal(out.Bytes(), &entries)
}

// recorder is a fake VM runtime: it records calls and answers from a table.
type recorder struct {
	calls     [][]string
	stdin     map[string]string // joined args -> stdin received
	vms       map[string]bool   // name -> running
	exited    map[string]bool
	status    string
	statusErr error // returned by the guest script's status mode when set
	session   string
	diag      map[string][]byte // guest script mode -> stdout
	launchOut string            // written by the VM helper instead of "started"
	readyErrs []error           // returned in turn by the readiness command
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
	case "Clone":
		if _, ok := r.vms[args[1]]; !ok {
			return nil, errors.New("baseline does not exist")
		}
		r.vms[args[2]] = false
		return nil, nil
	case "List":
		var out []vm.Entry
		for n, running := range r.vms {
			out = append(out, vm.Entry{Name: n, Running: running})
		}
		return json.Marshal(out)
	case "Delete":
		if _, ok := r.vms[args[1]]; !ok {
			return nil, fs.ErrNotExist
		}
		delete(r.vms, args[1])
		return nil, nil
	case "Stop":
		r.vms[args[1]] = false
		for _, p := range r.started {
			if p.args[len(p.args)-1] == args[1] {
				_ = p.Kill()
			}
		}
		return nil, nil
	case "Exec":
		i := 1
		if len(args) == i+2 && args[i+1] == "true" && len(r.readyErrs) > 0 {
			err := r.readyErrs[0]
			r.readyErrs = r.readyErrs[1:]
			return nil, err
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
	store := t.TempDir()
	for name := range r.vms {
		if err := os.MkdirAll(filepath.Join(store, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.VZ{Baseline: "base", CPU: 4, MemoryGB: 8, RunnerDir: "/Users/admin/actions-runner", HostVMLimit: 2}
	p, err := New("macos", cfg, "ctl-1", store, callRuntime{r})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLifecycleArguments(t *testing.T) {
	r := newRecorder()
	p := newProvider(t, r)
	ctx := context.Background()
	spec := provider.Spec{Name: "bivouac-macos-abc", Baseline: "base", CPU: 4, MemoryMB: 8192, Meta: provider.Metadata{ControllerID: "ctl-1", InstanceID: "abc"}}
	// Simulate the clone creating the directory before the marker is written.
	if err := os.MkdirAll(p.vmDir(spec.Name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := p.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"Clone", "base", "bivouac-macos-abc"}, {"Resize", "bivouac-macos-abc", "cpu=4", "memory=8192"}}
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
	if got := strings.Join(run, " "); got != "Start input bivouac-macos-abc" {
		t.Fatalf("start = %q", got)
	}
	if err := p.WaitReady(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	if got := r.stdin["Exec bivouac-macos-abc tee /tmp/bivouac-guest"]; !strings.Contains(got, "ACTIONS_RUNNER_INPUT_JITCONFIG") {
		t.Fatalf("guest script not delivered: %q", got)
	}
	if err := p.StartRunner(ctx, spec.Name, []byte("secret-jit")); err != nil {
		t.Fatal(err)
	}
	if got := r.stdin["Exec bivouac-macos-abc /tmp/bivouac-guest start /Users/admin/actions-runner"]; got != "secret-jit" {
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
	// A prefixed VM with another controller's marker.
	_ = os.WriteFile(filepath.Join(p.vmDir("bivouac-macos-other"), markerFile), []byte(`{"controller_id":"someone-else"}`), 0o600)

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
		if c[0] == "Delete" {
			t.Fatalf("delete was invoked: %v", c)
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
