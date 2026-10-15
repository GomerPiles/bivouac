package tart

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/provider"
)

const fixtureName = "bivouac-macos-fixture"

func writeMarker(t *testing.T, p *Provider, name string) {
	t.Helper()
	if err := os.MkdirAll(p.vmDir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(provider.Metadata{ControllerID: p.controllerID, InstanceID: "fixture"})
	if err := os.WriteFile(filepath.Join(p.vmDir(name), markerFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func ownedFixture(t *testing.T) (*Provider, *recorder) {
	t.Helper()
	r := newRecorder()
	p := newProvider(t, r)
	r.vms[fixtureName] = true
	writeMarker(t, p, fixtureName)
	return p, r
}

func TestRunnerStatusTransportFailureIsRetryable(t *testing.T) {
	p, r := ownedFixture(t)
	r.statusErr = &Error{Args: []string{"exec"}, Err: errors.New("exit status 1"), Stderr: "guest-private-stderr"}
	_, err := p.RunnerStatus(context.Background(), fixtureName)
	var transport provider.TransportFailure
	if !errors.As(err, &transport) || !transport.Retryable() || transport != provider.GuestAgentUnavailable {
		t.Fatalf("running owned VM with failed exec: %v, want retryable guest agent failure", err)
	}
	if strings.Contains(err.Error(), "guest-private-stderr") {
		t.Fatal("guest stderr in error")
	}

	// A probe deadline is a transport timeout, not a terminal error.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err = p.RunnerStatus(ctx, fixtureName); !errors.As(err, &transport) || transport != provider.GuestAgentTimeout {
		t.Fatalf("expired probe: %v", err)
	}
	// Caller cancellation stays cancellation.
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err = p.RunnerStatus(ctx, fixtureName); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled probe: %v", err)
	}

	// A stopped or missing VM confirms the runner is gone.
	r.vms[fixtureName] = false
	if st, err := p.RunnerStatus(context.Background(), fixtureName); err != nil || st.State != provider.RunnerAbsent {
		t.Fatalf("stopped VM: %+v %v", st, err)
	}
	delete(r.vms, fixtureName)
	if st, err := p.RunnerStatus(context.Background(), fixtureName); err != nil || st.State != provider.RunnerAbsent {
		t.Fatalf("missing VM: %+v %v", st, err)
	}

	// The guest script reporting absence is a confirmed exit.
	r.vms[fixtureName] = true
	r.statusErr = nil
	r.status = "absent"
	if st, err := p.RunnerStatus(context.Background(), fixtureName); err != nil || st.State != provider.RunnerAbsent {
		t.Fatalf("reported absence: %+v %v", st, err)
	}
}

func TestRunnerStatusTerminalErrors(t *testing.T) {
	p, r := ownedFixture(t)
	for _, status := range []string{strings.Repeat("x", statusOutputLimit+1), "garbage", ""} {
		r.status = status
		_, err := p.RunnerStatus(context.Background(), fixtureName)
		var transport provider.TransportFailure
		if err == nil || errors.As(err, &transport) {
			t.Fatalf("status %.20q: %v, want terminal error", status, err)
		}
		if len(err.Error()) > 200 || strings.Contains(err.Error(), "xxxx") || strings.Contains(err.Error(), "garbage") {
			t.Fatalf("guest output in error: %.200q", err.Error())
		}
	}
}

func TestGuestOperationsRequireOwnership(t *testing.T) {
	for _, marker := range []string{"", `{"controller_id":"someone-else"}`, `{"controller_id":"ctl-1","parent_name":"bivouac-macos-x"}`} {
		r := newRecorder()
		p := newProvider(t, r)
		r.vms[fixtureName] = true
		if err := os.MkdirAll(p.vmDir(fixtureName), 0o700); err != nil {
			t.Fatal(err)
		}
		if marker != "" {
			if err := os.WriteFile(filepath.Join(p.vmDir(fixtureName), markerFile), []byte(marker), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		ctx := context.Background()
		_, statusErr := p.RunnerStatus(ctx, fixtureName)
		for _, err := range []error{p.StartRunner(ctx, fixtureName, []byte("secret-jit")), statusErr, p.CollectDiagnostics(ctx, fixtureName, t.TempDir()), p.WaitReady(ctx, fixtureName)} {
			if !errors.Is(err, provider.ErrNotOwned) {
				t.Fatalf("marker %q: %v, want ErrNotOwned", marker, err)
			}
		}
		for _, c := range r.calls {
			if c[0] == "exec" {
				t.Fatalf("marker %q: guest exec on an unowned VM: %v", marker, c)
			}
		}
	}
}

func TestWaitReadyRetriesOnlyAnUnreachableAgent(t *testing.T) {
	p, r := ownedFixture(t)
	outdated := &guestagent.VersionError{Agent: guestagent.Version + 1, Host: guestagent.Version}
	r.readyErrs = []error{fmt.Errorf("%w: connection reset", guestagent.ErrUnavailable), outdated, nil}
	err := p.WaitReady(context.Background(), fixtureName)
	var version *guestagent.VersionError
	if !errors.As(err, &version) || len(r.readyErrs) != 1 {
		t.Fatalf("err = %v, %d probes left", err, len(r.readyErrs))
	}

	p, r = ownedFixture(t)
	r.readyErrs = []error{guestagent.ErrUnavailable, guestagent.ErrUnavailable, guestagent.ErrUnavailable}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := p.WaitReady(ctx, fixtureName); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unreachable agent: %v", err)
	}
}

func TestWaitReadyRequiresAquaSession(t *testing.T) {
	for _, session := range []string{"Background", "LoginWindow", strings.Repeat("A", 100), "evil\x1b[0m"} {
		p, r := ownedFixture(t)
		r.session = session
		err := p.WaitReady(context.Background(), fixtureName)
		if err == nil || !strings.Contains(err.Error(), "not Aqua") {
			t.Fatalf("session %q: %v", session, err)
		}
		if strings.Contains(err.Error(), "\x1b") || strings.Contains(err.Error(), strings.Repeat("A", 40)) {
			t.Fatalf("unsanitised session in error: %q", err)
		}
	}
	p, _ := ownedFixture(t)
	if err := p.WaitReady(context.Background(), fixtureName); err != nil {
		t.Fatal(err)
	}
}

func TestStartRunnerDoesNotEchoGuestOutput(t *testing.T) {
	p, r := ownedFixture(t)
	failing := &startOutput{recorder: r, out: "unexpected ghs_" + strings.Repeat("a", 30)}
	p.rt = argvRuntime{failing}
	err := p.StartRunner(context.Background(), fixtureName, []byte("secret-jit"))
	if err == nil || strings.Contains(err.Error(), "ghs_") || strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("StartRunner error: %v", err)
	}
}

type startOutput struct {
	*recorder
	out string
}

func (s *startOutput) Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) > 4 && args[3] == guestPath && args[4] == "start" {
		_, err := stdout.Write([]byte(s.out))
		return err
	}
	return s.recorder.Run(ctx, args, stdin, stdout)
}

func TestLaunchLogIsRedactedAndBounded(t *testing.T) {
	p, r := ownedFixture(t)
	r.vms[fixtureName] = false
	r.launchOut = "token ghs_" + strings.Repeat("a", 30) + "\n" + strings.Repeat("log line\n", 2*launchLogLimit/9)
	var sink bytes.Buffer
	if err := p.Start(context.Background(), fixtureName, &sink); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sink.String(), "ghs_") || !strings.Contains(sink.String(), "<redacted>") {
		t.Fatal("launch output not redacted")
	}
	if sink.Len() > launchLogLimit+4096 {
		t.Fatalf("launch log %d bytes", sink.Len())
	}
}

type tarEntry struct {
	name string
	kind byte
	data []byte
}

func gzipTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o600, Typeflag: e.kind}
		switch e.kind {
		case tar.TypeReg:
			h.Size = int64(len(e.data))
		case tar.TypeSymlink:
			h.Linkname = "/etc/passwd"
		case tar.TypeDir:
			h.Mode = 0o700
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func TestCollectDiagnosticsRedactsBeforeDisk(t *testing.T) {
	p, r := ownedFixture(t)
	secret := "ghs_" + strings.Repeat("d", 36)
	r.diag["diag"] = gzipTar(t, []tarEntry{
		{name: "runner.log", kind: tar.TypeReg, data: []byte("job token " + secret + "\nmore " + strings.Repeat("y", 200<<10) + secret)},
		{name: "link", kind: tar.TypeSymlink},
	})
	r.diag["diag-runner"] = gzipTar(t, []tarEntry{
		{name: "_diag", kind: tar.TypeDir},
		{name: "_diag/Worker_1.log", kind: tar.TypeReg, data: []byte("Authorization: Bearer " + secret + "\n")},
	})
	dir := t.TempDir()
	if err := p.CollectDiagnostics(context.Background(), fixtureName, dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"guest/runner.log", "runner/_diag/Worker_1.log"} {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil || strings.Contains(string(data), secret[:12]) || !strings.Contains(string(data), "<redacted>") {
			t.Fatalf("%s: not redacted: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "guest", "link")); !os.IsNotExist(err) {
		t.Fatal("symbolic link extracted", err)
	}
}

func TestDiagnosticsTarBombs(t *testing.T) {
	many := make([]tarEntry, 20)
	for i := range many {
		many[i] = tarEntry{name: "f" + strings.Repeat("x", i), kind: tar.TypeReg}
	}
	big := bytes.Repeat([]byte("z"), 4096)
	cases := map[string]struct {
		archive []byte
		budget  diagBudget
		want    error
	}{
		"entries":     {gzipTar(t, many), diagBudget{entries: 10, bytes: 1 << 20, stream: 1 << 20}, errDiagEntries},
		"bytes":       {gzipTar(t, []tarEntry{{"a", tar.TypeReg, big}, {"b", tar.TypeReg, big}}), diagBudget{entries: 10, bytes: 6000, stream: 1 << 20}, errDiagBytes},
		"stream":      {gzipTar(t, []tarEntry{{"a", tar.TypeReg, bytes.Repeat([]byte{0}, 1<<20)}}), diagBudget{entries: 10, bytes: 2 << 20, stream: 64 << 10}, errDiagStream},
		"skipped":     {gzipTar(t, []tarEntry{{"d", tar.TypeDir, nil}, {"l", tar.TypeSymlink, nil}, {"m", tar.TypeSymlink, nil}}), diagBudget{entries: 2, bytes: 1, stream: 1 << 20}, errDiagEntries},
		"traversal":   {gzipTar(t, []tarEntry{{"../escape", tar.TypeReg, []byte("x")}}), diagBudget{entries: 10, bytes: 10, stream: 1 << 20}, nil},
		"absolute":    {gzipTar(t, []tarEntry{{"/tmp/escape", tar.TypeReg, []byte("x")}}), diagBudget{entries: 10, bytes: 10, stream: 1 << 20}, nil},
		"not-gzip":    {[]byte("plain text, not an archive"), diagBudget{entries: 10, bytes: 10, stream: 1 << 20}, nil},
		"compressed":  {bytes.Repeat([]byte{0x1f}, 128<<10), diagBudget{entries: 10, bytes: 10, stream: 64 << 10}, errDiagStream},
		"duplicate":   {gzipTar(t, []tarEntry{{"a", tar.TypeReg, []byte("1")}, {"a", tar.TypeReg, []byte("2")}}), diagBudget{entries: 10, bytes: 10, stream: 1 << 20}, nil},
		"empty-input": {nil, diagBudget{entries: 10, bytes: 10, stream: 1 << 20}, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p, r := ownedFixture(t)
			r.diag["diag"] = c.archive
			parent := t.TempDir()
			dir := filepath.Join(parent, "out")
			budget := c.budget
			err := p.collectArchive(context.Background(), fixtureName, []string{guestPath, "diag", "/r"}, dir, &budget)
			switch {
			case name == "empty-input":
				if err != nil {
					t.Fatal(err)
				}
			case err == nil:
				t.Fatal("unsafe archive accepted")
			case c.want != nil && !errors.Is(err, c.want):
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if _, err := os.Stat(filepath.Join(parent, "escape")); !os.IsNotExist(err) {
				t.Fatal("entry escaped the directory")
			}
		})
	}
}
