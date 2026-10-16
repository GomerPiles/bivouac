package vz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/GomerPiles/bivouac/internal/guestagent"
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

func (c callRuntime) Clone(ctx context.Context, baseline, name string, opts vm.CloneOptions) error {
	return c.calls.Run(ctx, []string{"Clone", baseline, name, "cpu=" + strconv.Itoa(opts.CPU), "memory=" + strconv.Itoa(opts.MemoryMiB)}, nil, io.Discard)
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
	if d := launch.Machine.Display; d.Width != 0 {
		call = append(call, fmt.Sprintf("display=%dx%d@%d", d.Width, d.Height, d.PPI))
	}
	if launch.Machine.DiskSync != "" {
		call = append(call, "disk-sync="+launch.Machine.DiskSync)
	}
	if launch.Machine.Nested {
		call = append(call, "nested")
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
	store     vm.Store // set by newProvider; Clone copies manifests in it
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
		// Like the real store, a clone carries its baseline's manifest.
		if data, err := os.ReadFile(filepath.Join(r.store.Dir(args[1]), vm.ManifestFile)); err == nil {
			if err := os.MkdirAll(r.store.Dir(args[2]), 0o700); err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(r.store.Dir(args[2]), vm.ManifestFile), data, 0o600); err != nil {
				return nil, err
			}
		}
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

// writeTestManifest makes dir a VM of guestOS with the current guest agent.
func writeTestManifest(t *testing.T, dir, guestOS string) {
	t.Helper()
	m := vm.Manifest{Version: vm.ManifestVersion, OS: guestOS, Arch: "arm64", CPU: 2, MemoryMiB: 4096, MAC: "02:00:00:00:00:01", Guest: vm.Guest{AgentVersion: guestagent.Version}}
	if guestOS == "darwin" {
		m.MacOS = &vm.MacOSPlatform{HardwareModel: []byte("hw"), MachineID: []byte("id")}
		m.Guest.RunnerDir = "/Users/admin/actions-runner"
		m.Guest.Sudo = true
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, vm.ManifestFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newProvider(t *testing.T, r *recorder) *Provider {
	t.Helper()
	store := t.TempDir()
	r.store = vm.Store(store)
	for name := range r.vms {
		guestOS := "darwin"
		if strings.HasPrefix(name, "linux") {
			guestOS = "linux"
		}
		writeTestManifest(t, filepath.Join(store, name), guestOS)
	}
	cfg := config.VZ{Baseline: "base", CPU: 4, MemoryGB: 8, HostVMLimit: 2}
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
	want := [][]string{{"Clone", "base", "bivouac-macos-abc", "cpu=4", "memory=8192"}}
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

func TestCreateRefusesBaselinesItCannotDrive(t *testing.T) {
	spec := provider.Spec{Name: "bivouac-macos-abc", Baseline: "base", Meta: provider.Metadata{ControllerID: "ctl-1", InstanceID: "abc"}}
	for name, c := range map[string]struct {
		edit func(*vm.Manifest)
		want string
	}{
		"no manifest":   {nil, "bivouac vz import"},
		"linux":         {func(m *vm.Manifest) { m.OS, m.MacOS = "linux", nil }, "not darwin"},
		"old agent":     {func(m *vm.Manifest) { m.Guest.AgentVersion = guestagent.Version + 1 }, "install the matching agent"},
		"no runner dir": {func(m *vm.Manifest) { m.Guest.RunnerDir = "" }, "--runner-dir"},
	} {
		r := newRecorder()
		p := newProvider(t, r)
		path := filepath.Join(p.vmDir("base"), vm.ManifestFile)
		if c.edit == nil {
			_ = os.Remove(path)
		} else {
			m, err := vm.ReadManifest(p.vmDir("base"))
			if err != nil {
				t.Fatal(err)
			}
			c.edit(&m)
			data, _ := json.Marshal(m)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		err := p.Create(context.Background(), spec)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
		if len(r.calls) != 0 {
			t.Errorf("%s: touched the runtime: %v", name, r.calls)
		}
	}
}

func TestRunnerLaunchCarriesMachineOptions(t *testing.T) {
	p, r := ownedFixture(t)
	r.vms[fixtureName] = false
	p.cfg.Machine = config.Machine{Display: config.Display{Width: 1920, Height: 1080, PPI: 144}, DiskSync: "none"}
	if err := p.Start(context.Background(), fixtureName, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls[len(r.calls)-1], " "); got != "Start input display=1920x1080@144 disk-sync=none "+fixtureName {
		t.Fatalf("start = %q", got)
	}
}

func TestReleaseProxyNeedsRecordedSudo(t *testing.T) {
	p, _ := ownedFixture(t)
	if err := p.checkReleaseProxy(fixtureName); err != nil {
		t.Fatal(err)
	}
	m, _ := vm.ReadManifest(p.vmDir(fixtureName))
	m.Guest.Sudo = false
	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(p.vmDir(fixtureName), vm.ManifestFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.checkReleaseProxy(fixtureName); err == nil {
		t.Fatal("release proxy allowed without sudo")
	}
}

func TestNestedVirtualizationOnlyForLinuxGuests(t *testing.T) {
	r := newRecorder()
	p := newProvider(t, r)
	p.cfg.Machine.NestedVirtualization = true
	spec := provider.Spec{Name: "bivouac-macos-abc", Baseline: "base", Meta: provider.Metadata{ControllerID: "ctl-1", InstanceID: "abc"}}
	if err := p.Create(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "only to Linux guests") {
		t.Fatalf("nested macOS runner: %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("touched the runtime: %v", r.calls)
	}
}

func TestCheckNestedFollowsTheHost(t *testing.T) {
	if err := CheckNested(config.VZ{}); err != nil {
		t.Fatalf("no nesting requested: %v", err)
	}
	cfg := config.VZ{Containers: &config.Containers{Machine: config.Machine{NestedVirtualization: true}}}
	supported, hostErr := vm.NestedVirtualizationSupported()
	err := CheckNested(cfg)
	switch {
	case hostErr != nil:
		if !errors.Is(err, hostErr) {
			t.Fatalf("CheckNested = %v, want %v", err, hostErr)
		}
	case supported && err != nil:
		t.Fatalf("supporting host refused: %v", err)
	case !supported && !errors.Is(err, vm.ErrNestedUnsupported):
		t.Fatalf("CheckNested = %v, want ErrNestedUnsupported", err)
	}
}
