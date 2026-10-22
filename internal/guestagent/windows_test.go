//go:build windows

package guestagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/hvsock"
	winio "github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"golang.org/x/sys/windows"
)

func TestSessionRule(t *testing.T) {
	good := sessionFacts{process: 2, console: 2, elevation: elevationFull, elevated: true, user: "expected"}
	tests := []struct {
		name    string
		change  func(*sessionFacts)
		allowed bool
	}{
		{"full", func(*sessionFacts) {}, true},
		{"not split admin", func(f *sessionFacts) { f.elevation = elevationDefault }, true},
		{"not elevated", func(f *sessionFacts) { f.elevated = false }, false},
		{"not split ordinary", func(f *sessionFacts) { f.elevation = elevationDefault; f.elevated = false }, false},
		{"limited", func(f *sessionFacts) { f.elevation = 3 }, false},
		{"unknown type", func(f *sessionFacts) { f.elevation = 99 }, false},
		{"different session", func(f *sessionFacts) { f.process = 3 }, false},
		{"no console", func(f *sessionFacts) { f.console = ^uint32(0) }, false},
		{"session zero", func(f *sessionFacts) { f.process = 0; f.console = 0 }, false},
		{"different account", func(f *sessionFacts) { f.user = "other" }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := good
			tt.change(&f)
			if sessionAllowed(f, "expected") != tt.allowed {
				t.Fatal("wrong session decision")
			}
		})
	}
	if sessionAllowed(good, "") {
		t.Fatal("missing fixed account admitted")
	}
	if _, err := currentSession(); err != nil {
		t.Fatal("native session facts unavailable", err)
	}
	for _, args := range [][]string{nil, {"--user"}, {"--other=secret"}, {"receive"}, {"receive", "name", "invalid", "hash"}} {
		if err := RunCLI(t.Context(), args, strings.NewReader("")); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsafe CLI rejection", err)
		}
	}
}

type pipeListener struct {
	connections chan io.ReadWriteCloser
	closed      chan struct{}
}

func (l *pipeListener) Accept() (io.ReadWriteCloser, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func TestSessionCheckedOnEachConnection(t *testing.T) {
	base := &pipeListener{make(chan io.ReadWriteCloser, 1), make(chan struct{})}
	checks := 0
	l := &sessionListener{Listener: base, check: func() bool { checks++; return checks == 1 }, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for i := range 2 {
		host, guest := net.Pipe()
		base.connections <- guest
		done := make(chan error, 1)
		go func() {
			conn, err := l.Accept()
			if conn != nil {
				_ = conn.Close()
			}
			done <- err
		}()
		if i == 1 {
			kind, p, err := readFrame(host, nil)
			if err != nil || kind != frameFailed || string(p) != "session refused" {
				t.Fatal("missing fixed refusal", err)
			}
		}
		if err := <-done; (err == nil) != (i == 0) {
			t.Fatal("session check not enforced")
		}
		_ = host.Close()
	}
	if checks != 2 {
		t.Fatal("missing connection check")
	}
}

func TestWindowsListenerWiring(t *testing.T) {
	called := false
	l, err := listenWindows(func(a *winio.HvsockAddr) (net.Listener, error) {
		called = true
		service, err := guid.FromString(ServiceID)
		if err != nil || a.ServiceID != service || a.VMID != winio.HvsockGUIDParent() {
			t.Fatal("listener is not parent-only")
		}
		return nil, errors.New("sensitive native error")
	})
	if !called || l != nil || err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("listener wiring failed")
	}
	host, peer := net.Pipe()
	defer func() { _ = host.Close(); _ = peer.Close() }()
	l, err = listenWindows(func(*winio.HvsockAddr) (net.Listener, error) { return fixedNetListener{host}, nil })
	if err != nil {
		t.Fatal(err)
	}
	conn, err := l.Accept()
	if err != nil || conn != host {
		t.Fatal("accepted connection not forwarded", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

type fixedNetListener struct{ conn net.Conn }

func (l fixedNetListener) Accept() (net.Conn, error) { return l.conn, nil }
func (fixedNetListener) Close() error                { return nil }
func (fixedNetListener) Addr() net.Addr              { return nil }

func TestWindowsDialerRetriesAndCancellation(t *testing.T) {
	const runtimeID = "bfe36c74-23ef-4f18-93ad-d16901422460"
	vm, _ := hvsock.ParseGUID(runtimeID)
	service, _ := hvsock.ParseGUID(ServiceID)
	calls := 0
	host, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	dial := dialHvsock(runtimeID, func(ctx context.Context, a hvsock.Addr) (net.Conn, error) {
		calls++
		if a.VMID != vm || a.ServiceID != service {
			t.Fatal("wrong dial address")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 30*time.Millisecond {
			t.Fatal("unbounded attempt")
		}
		if calls == 1 {
			return nil, errors.New("refused")
		}
		return host, nil
	}, 30*time.Millisecond, time.Millisecond)
	c, err := dial(t.Context())
	if err != nil || c != host || calls != 2 {
		t.Fatal("retry failed", err)
	}
	_ = c.Close()
	for _, pending := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
		d := dialHvsock(runtimeID, func(attempt context.Context, _ hvsock.Addr) (net.Conn, error) {
			if pending {
				<-attempt.Done()
			}
			return nil, errors.New("private failure")
		}, 20*time.Millisecond, time.Second)
		start := time.Now()
		c, err := d(ctx)
		cancel()
		if c != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
			t.Fatal("dial escaped context", err)
		}
	}
	if _, err := DialHvsock("private invalid runtime")(t.Context()); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("invalid runtime leaked")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := DialHvsock(runtimeID)(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled dial allocated socket", err)
	}
}

func hashText(b []byte) string             { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func receiveDirectory(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "guest") }

func TestReceiverPublishesAllowlistAtomically(t *testing.T) {
	dir := receiveDirectory(t)
	for _, name := range []string{"bivouac-helper.exe", "bivouac-config.json", "bivouac-runner.zip"} {
		first, second := []byte("old"), []byte("new verified content\x00\xff")
		if err := receive(t.Context(), dir, name, int64(len(first)), hashText(first), bytes.NewReader(first)); err != nil {
			t.Fatal(err)
		}
		// Observe the old complete file while a replacement is being received.
		reader, writer := io.Pipe()
		done := make(chan error, 1)
		go func() { done <- receive(t.Context(), dir, name, int64(len(second)), hashText(second), reader) }()
		if _, err := writer.Write(second[:3]); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, first) {
			t.Fatal("partial file was published", err)
		}
		if _, err := writer.Write(second[3:]); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		_ = reader.Close()
		got, err = os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, second) {
			t.Fatal("replacement not complete", err)
		}
	}
	assertNoReceiveTemps(t, dir)
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("private reader failure") }

func assertNoReceiveTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".receive-") {
			t.Fatal("temporary file survived")
		}
	}
}

func TestReceiverRefusalsAndCleanup(t *testing.T) {
	dir := receiveDirectory(t)
	data := []byte("verified")
	name := "bivouac-helper.exe"
	if err := receive(t.Context(), dir, name, int64(len(data)), hashText(data), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		file  string
		size  int64
		hash  string
		input io.Reader
	}{
		{"unknown", "unknown.exe", 0, hashText(nil), strings.NewReader("")},
		{"ADS", name + ":stream", 0, hashText(nil), strings.NewReader("")},
		{"traversal", `..\` + name, 0, hashText(nil), strings.NewReader("")},
		{"case", "BIVOUAC-HELPER.EXE", 0, hashText(nil), strings.NewReader("")},
		{"negative", name, -1, hashText(nil), strings.NewReader("")},
		{"oversize", name, maxReceiveSize + 1, hashText(nil), strings.NewReader("")},
		{"invalid hash", name, 0, "not a hash", strings.NewReader("")},
		{"hash mismatch", name, int64(len(data)), hashText(nil), bytes.NewReader(data)},
		{"short", name, int64(len(data)) + 1, hashText(data), bytes.NewReader(data)},
		{"long", name, int64(len(data)) - 1, hashText(data), bytes.NewReader(data)},
		{"read failure", name, 8, hashText(data), brokenReader{}},
		{"partial read failure", name, 8, hashText(data), io.MultiReader(strings.NewReader("partial"), brokenReader{})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := receive(t.Context(), dir, tt.file, tt.size, tt.hash, tt.input)
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("unsafe receiver acceptance", err)
			}
			got, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatal("failure damaged published file", err)
			}
			assertNoReceiveTemps(t, dir)
		})
	}
	if err := os.WriteFile(filepath.Join(dir, "launched"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := receive(t.Context(), dir, name, int64(len(data)), hashText(data), bytes.NewReader(data)); err == nil {
		t.Fatal("replaced after launch")
	}
	assertNoReceiveTemps(t, dir)
}

func TestReceiverRejectsLinksAndUnprotectedDirectory(t *testing.T) {
	dir := receiveDirectory(t)
	d, err := openGuestDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	source := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(source, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "bivouac-helper.exe")
	if err := os.Link(source, target); err != nil {
		t.Fatal(err)
	}
	if err := receive(t.Context(), dir, "bivouac-helper.exe", 0, hashText(nil), strings.NewReader("")); err == nil {
		t.Fatal("accepted hardlink")
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := createTestJunction(target, filepath.Dir(source)); err != nil {
		t.Fatal(err)
	}
	if err := receive(t.Context(), dir, "bivouac-helper.exe", 0, hashText(nil), strings.NewReader("")); err == nil {
		t.Fatal("accepted reparse destination")
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	// Directory junctions exercise reparse refusal without symlink privileges.
	junction := filepath.Join(t.TempDir(), "junction")
	if err := createTestJunction(junction, dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(junction) }()
	if _, err := openGuestDirectory(junction); err == nil {
		t.Fatal("accepted reparse directory")
	}
	if _, err := openGuestDirectory(filepath.Join(junction, "nested")); err == nil {
		t.Fatal("accepted reparse ancestor")
	}
	if _, err := openGuestDirectory(t.TempDir()); err == nil {
		t.Fatal("accepted unprotected existing directory")
	}
	got, err := os.ReadFile(source)
	if err != nil || string(got) != "unchanged" {
		t.Fatal("outside file changed", err)
	}
}

func TestAgentLogBoundedAndProtected(t *testing.T) {
	d, err := openGuestDirectory(receiveDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	l, err := newAgentLog(d)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(l, nil))
	logger.Info("agent_start", "protocol", Version)
	for range 5 {
		if _, err := l.Write(bytes.Repeat([]byte("x"), int(agentLogLimit/2))); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agent.log", "agent.log.1"} {
		stat, err := os.Stat(filepath.Join(d.path, name))
		if err != nil || stat.Size() > agentLogLimit {
			t.Fatal("log cap failed", err)
		}
	}
}

func helperArgs(mode string, args ...string) []string {
	return append([]string{os.Args[0], "-test.run=^TestWindowsCommandHelper$", "--", "--guest-helper", mode}, args...)
}

func TestWindowsCommandHelper(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "--guest-helper" {
			index = i + 1
			break
		}
	}
	if index == -1 {
		return
	}
	args := os.Args[index:]
	switch args[0] {
	case "echo":
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "args":
		_ = json.NewEncoder(os.Stdout).Encode(args[1:])
	case "facts":
		facts, err := currentSession()
		if err != nil {
			os.Exit(45)
		}
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			Session  uint32
			User     string
			Elevated bool
			Env      string
		}{facts.process, facts.user, facts.elevated, os.Getenv("BIVOUAC_AGENT_TEST_INHERIT")})
	case "exit":
		os.Exit(37)
	case "receive":
		size, err := strconv.ParseInt(args[3], 10, 64)
		if err != nil {
			os.Exit(43)
		}
		if err := receive(t.Context(), args[1], args[2], size, args[4], os.Stdin); err != nil {
			os.Exit(44)
		}
	case "sleep":
		time.Sleep(time.Minute)
	case "tree", "breakaway":
		cmd := exec.Command(helperArgs("sleep")[0], helperArgs("sleep")[1:]...)
		if args[0] == "breakaway" {
			cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_BREAKAWAY_FROM_JOB | windows.CREATE_NO_WINDOW, HideWindow: true}
		}
		if err := cmd.Start(); err != nil {
			_, _ = fmt.Fprintln(os.Stdout, 0)
			os.Exit(41)
		}
		_, _ = fmt.Fprintln(os.Stdout, cmd.Process.Pid)
		_ = cmd.Process.Release()
		time.Sleep(time.Minute)
	default:
		os.Exit(42)
	}
	os.Exit(0)
}

func TestReceiverKilledMidTransferRemovesTemporaryFile(t *testing.T) {
	dir := receiveDirectory(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	p, stdin, err := startCommand(ctx, request{Argv: helperArgs("receive", dir, "bivouac-helper.exe", "1000", hashText(nil)), Stdin: true}, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := stdin.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, _ := os.ReadDir(dir)
		found := false
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".receive-") {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("receiver did not create temporary file")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if _, err := p.Wait(); err != nil {
		t.Fatal(err)
	}
	assertNoReceiveTemps(t, dir)
}

func TestWindowsArgvStreamsAndExit(t *testing.T) {
	args := []string{"", "a b", `a"b`, `tail\`, `space tail\`, "&|<>%anything%", "\u263a"}
	var out bytes.Buffer
	p, _, err := startCommand(t.Context(), request{Argv: helperArgs("args", args...)}, &out, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	code, err := p.Wait()
	p.Close()
	if err != nil || code != 0 {
		t.Fatal("argument helper failed", code, err)
	}
	var got []string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || !reflect.DeepEqual(got, args) {
		t.Fatal("argv corrupted", err)
	}
	data := bytes.Repeat([]byte{0, 255, 2, 3}, 40000)
	out.Reset()
	p, stdin, err := startCommand(t.Context(), request{Argv: helperArgs("echo"), Stdin: true}, &out, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = stdin.Write(data); _ = stdin.Close() }()
	code, err = p.Wait()
	p.Close()
	if err != nil || code != 0 || !bytes.Equal(data, out.Bytes()) {
		t.Fatal("binary stream failed", code, err)
	}
	p, _, err = startCommand(t.Context(), request{Argv: helperArgs("exit")}, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	code, err = p.Wait()
	p.Close()
	if err != nil || code != 37 {
		t.Fatal("exit status lost", code, err)
	}
	t.Setenv("BIVOUAC_AGENT_TEST_INHERIT", "fixed-fixture")
	out.Reset()
	p, _, err = startCommand(t.Context(), request{Argv: helperArgs("facts")}, &out, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	code, err = p.Wait()
	p.Close()
	if err != nil || code != 0 {
		t.Fatal("inherited facts unavailable", err)
	}
	var facts struct {
		Session  uint32
		User     string
		Elevated bool
		Env      string
	}
	if err := json.Unmarshal(out.Bytes(), &facts); err != nil {
		t.Fatal(err)
	}
	parent, err := currentSession()
	if err != nil || facts.Session != parent.process || facts.User != parent.user || facts.Elevated != parent.elevated || facts.Env != "fixed-fixture" {
		t.Fatal("command did not inherit session, token and environment")
	}
}

func TestWindowsJobKillsTreeAndAllowsExplicitBreakaway(t *testing.T) {
	for _, mode := range []string{"tree", "breakaway"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r, w := io.Pipe()
			p, _, err := startCommand(ctx, request{Argv: helperArgs(mode)}, w, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			defer func() { _ = r.Close(); _ = w.Close() }()
			var pid uint32
			if _, err := fmt.Fscanln(r, &pid); err != nil || pid == 0 {
				t.Fatal("descendant launch failed", err)
			}
			h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, pid)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = windows.TerminateProcess(h, 1)
				_, _ = windows.WaitForSingleObject(h, 5000)
				_ = windows.CloseHandle(h)
			}()
			cancel()
			if _, err := p.Wait(); err != nil {
				t.Fatal(err)
			}
			state, err := windows.WaitForSingleObject(h, 1000)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "tree" && state != windows.WAIT_OBJECT_0 {
				t.Fatal("descendant survived job close")
			}
			if mode == "breakaway" && state != uint32(windows.WAIT_TIMEOUT) {
				t.Fatal("explicit breakaway was killed")
			}
		})
	}
}

func TestWindowsProtocolOverPipes(t *testing.T) {
	base := &pipeListener{make(chan io.ReadWriteCloser), make(chan struct{})}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, base) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	dial := func(ctx context.Context) (net.Conn, error) {
		host, guest := net.Pipe()
		select {
		case base.connections <- guest:
			return host, nil
		case <-ctx.Done():
			_ = host.Close()
			_ = guest.Close()
			return nil, ctx.Err()
		}
	}
	var out bytes.Buffer
	data := bytes.Repeat([]byte("binary\x00\xff"), 30000)
	if err := Run(t.Context(), dial, helperArgs("echo"), bytes.NewReader(data), &out); err != nil || !bytes.Equal(data, out.Bytes()) {
		t.Fatal("protocol stream failed", err)
	}
	var exit *ExitError
	if err := Run(t.Context(), dial, helperArgs("exit"), nil, io.Discard); !errors.As(err, &exit) || exit.Code != 37 {
		t.Fatal("protocol exit failed", err)
	}
	if err := Run(t.Context(), dial, []string{"missing-command.exe"}, nil, io.Discard); !errors.Is(err, ErrFailed) {
		t.Fatal("missing command not fixed failure", err)
	}
	conn, err := dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"v":2,"argv":["missing-command.exe"]}`)
	if err := writeFrame(conn, frameRequest, payload); err != nil {
		t.Fatal(err)
	}
	kind, response, err := readFrame(conn, nil)
	_ = conn.Close()
	if err != nil || kind != frameFailed || string(response) != versionPrefix+strconv.Itoa(Version) {
		t.Fatal("version refusal failed", err)
	}
	commandCtx, commandCancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer commandCancel()
	if err := Run(commandCtx, dial, helperArgs("sleep"), nil, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("connection cancellation failed", err)
	}
}
