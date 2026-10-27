//go:build windows

package hcsvm

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/provider"
)

// pipeAgent implements the guestagent wire protocol without executing anything
// on the host. Provider calls still traverse the production client and bounds.
type pipeAgent struct {
	mu        sync.Mutex
	requests  [][]string
	inputs    [][]byte
	transient int
	version   bool
	response  func([]string, []byte) (byte, []byte)
	dialBound time.Duration
}

func TestRealAgentFailuresReachSessionDropClassification(t *testing.T) {
	err := agentError(t.Context(), guestagent.ErrUnavailable)
	var transport provider.TransportFailure
	if !errors.As(err, &transport) || transport != provider.GuestAgentUnavailable {
		t.Fatal("real unavailable error no longer reaches drop classification")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err = agentError(ctx, context.Canceled)
	if !errors.As(err, &transport) || transport != provider.GuestAgentTimeout {
		t.Fatal("real timeout error no longer reaches drop classification")
	}
}

func (a *pipeAgent) Open(context.Context, string) (Session, error) {
	return &agentSession{dial: a.dial}, nil
}
func wireRead(r io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(header[1:])
	if n > 64<<10 {
		return 0, nil, errors.New("oversized fixture frame")
	}
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return header[0], p, err
}
func wireWrite(w io.Writer, kind byte, p []byte) error {
	var header [5]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(p))) //nolint:gosec // Fixture frames are bounded.
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}
func (a *pipeAgent) dial(ctx context.Context) (net.Conn, error) {
	a.mu.Lock()
	if deadline, ok := ctx.Deadline(); ok {
		a.dialBound = time.Until(deadline)
	}
	if a.transient > 0 {
		a.transient--
		a.mu.Unlock()
		return nil, errors.New("transient fixture dial")
	}
	a.mu.Unlock()
	host, guest := net.Pipe()
	go func() {
		defer func() { _ = guest.Close() }()
		kind, p, err := wireRead(guest)
		var request struct {
			Version int      `json:"v"`
			Argv    []string `json:"argv"`
			Stdin   bool     `json:"stdin"`
		}
		if err != nil || kind != 'R' || json.Unmarshal(p, &request) != nil || request.Version != guestagent.Version {
			return
		}
		a.mu.Lock()
		refused := a.version
		a.mu.Unlock()
		if refused {
			_ = wireWrite(guest, 'F', []byte("version 2"))
			return
		}
		var input []byte
		if request.Stdin {
			for {
				kind, p, err = wireRead(guest)
				if err != nil || kind != 'I' {
					return
				}
				if len(p) == 0 {
					break
				}
				input = append(input, p...)
			}
		}
		a.mu.Lock()
		a.requests = append(a.requests, request.Argv)
		a.inputs = append(a.inputs, input)
		respond := a.response
		a.mu.Unlock()
		var out []byte
		result := byte('O')
		if respond != nil {
			result, out = respond(request.Argv, input)
		} else {
			switch request.Argv[len(request.Argv)-1] {
			case "preflight", "prepare":
				out = []byte(`{"ready":true,"session":1,"desktop":"Default"}`)
			case "clock":
				out = []byte(hostNow.Format(time.RFC3339Nano))
			case "gpu":
				out = []byte(`{"hardware_d3d12":true}`)
			case "status":
				out = []byte(`{"State":"listening"}`)
			}
		}
		if len(out) > 0 && wireWrite(guest, result, out) != nil {
			return
		}
		if result == 'O' {
			_ = wireWrite(guest, 'X', make([]byte, 4))
		}
	}()
	return host, nil
}
func usePipeAgent(t *testing.T) (*Provider, *pipeAgent) {
	t.Helper()
	p, _, _ := fixture(t, true)
	a := &pipeAgent{}
	p.transport = a
	p.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(p.Close)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	return p, a
}

func TestAgentReadinessReceivesExactFilesInOrder(t *testing.T) {
	p, a := usePipeAgent(t)
	archive := []byte("fixture runner archive")
	p.opts.RunnerArchive = filepath.Join(t.TempDir(), "runner.zip")
	digest := sha256.Sum256(archive)
	p.opts.RunnerSHA256 = hex.EncodeToString(digest[:])
	if err := os.WriteFile(p.opts.RunnerArchive, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := p.waitReady(t.Context(), spec().Name)
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	want := [][]string{
		{guestagent.WindowsPath, "version"},
		nil, nil, nil,
		{guestIncomingHelper, "guest", "windows", "preflight"},
		{guestIncomingHelper, "guest", "windows", "prepare"},
		guestCommand("gpu"),
		guestCommand("clock"),
	}
	if len(a.requests) != len(want) {
		t.Fatalf("got %d requests", len(a.requests))
	}
	for i, argv := range want {
		if argv != nil && !slices.Equal(argv, a.requests[i]) {
			t.Fatalf("wrong argv at step %d", i)
		}
	}
	for i, name := range []string{"bivouac-config.json", "bivouac-helper.exe", "bivouac-runner.zip"} {
		index := i + 1
		data := a.inputs[index]
		digest := sha256.Sum256(data)
		want := []string{guestagent.WindowsPath, "guest-agent", "receive", name, strconv.Itoa(len(data)), hex.EncodeToString(digest[:])}
		if !slices.Equal(a.requests[index], want) {
			t.Fatal("receive metadata differs")
		}
	}
	if string(a.inputs[2]) != "helper" || !bytes.Equal(a.inputs[3], archive) {
		t.Fatal("file bytes differ")
	}
	if len(a.inputs[7]) == 0 || a.dialBound <= 0 || a.dialBound > 15*time.Second {
		t.Fatal("proof deadline or clock stdin missing")
	}
	for _, key := range []string{"agent_dial_ms", "agent_proof_ms", "delivery_config_ms", "delivery_helper_ms", "delivery_runner_archive_ms", "preflight_ms", "prepare_ms", "clock_sync_ms"} {
		if _, ok := report.SpansMS[key]; !ok {
			t.Fatal("missing readiness timing", key)
		}
	}
}
func TestAgentVersionRefusalIsTerminalAndTransientDialRetries(t *testing.T) {
	p, a := usePipeAgent(t)
	a.version = true
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	started := time.Now()
	err := p.WaitReady(ctx, spec().Name)
	var transport provider.TransportFailure
	if !errors.Is(err, provider.GuestAgentUnavailable) || errors.As(err, &transport) || err.Error() != "guest agent unavailable: incompatible protocol version" || time.Since(started) > 500*time.Millisecond {
		t.Fatal("version refusal was not fixed and terminal", err)
	}
	a.version = false
	a.transient = 1
	if err := p.WaitReady(t.Context(), spec().Name); err != nil {
		t.Fatal("transient dial did not recover", err)
	}
}
func TestAgentCommandBoundsExitAndNoMutationReplay(t *testing.T) {
	for _, mode := range []string{"seed-jit", "start", "status"} {
		t.Run(mode, func(t *testing.T) {
			p, a := usePipeAgent(t)
			a.response = func(argv []string, _ []byte) (byte, []byte) {
				if argv[len(argv)-1] == mode {
					return 'X', []byte{0, 0, 0, 7}
				}
				return 'O', nil
			}
			var err error
			if mode == "status" {
				_, err = p.RunnerStatus(t.Context(), spec().Name)
			} else {
				err = p.StartRunner(t.Context(), spec().Name, []byte("fixture-jit"))
			}
			if err == nil || err.Error() != "guest command failed (exit 7)" {
				t.Fatal("exit mapping changed", err)
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			count := 0
			for _, argv := range a.requests {
				if argv[len(argv)-1] == mode {
					count++
				}
			}
			if count != 1 {
				t.Fatal("mutation/probe replayed")
			}
		})
	}
	p, a := usePipeAgent(t)
	a.response = func([]string, []byte) (byte, []byte) { return 'O', bytes.Repeat([]byte("x"), 4097) }
	if _, err := p.RunnerStatus(t.Context(), spec().Name); err == nil {
		t.Fatal("oversized status accepted")
	}
	a.response = func([]string, []byte) (byte, []byte) { return 'O', []byte("private invalid status") }
	if _, err := p.RunnerStatus(t.Context(), spec().Name); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("untrusted status leaked")
	}
}
func TestAgentAdoptionAndDiagnostics(t *testing.T) {
	p, a := usePipeAgent(t)
	// A new provider has no command session or host-key state to recover.
	adopted, err := New(p.opts, p.host, a)
	if err != nil {
		t.Fatal(err)
	}
	defer adopted.Close()
	if st, err := adopted.RunnerStatus(t.Context(), spec().Name); err != nil || st.State != provider.RunnerListening {
		t.Fatal("adoption failed", err)
	}
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	f, err := z.Create("runner.log")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("fixture diagnostic")); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	a.response = func([]string, []byte) (byte, []byte) {
		return 'O', []byte(base64.StdEncoding.EncodeToString(archive.Bytes()))
	}
	dir := t.TempDir()
	if err := adopted.CollectDiagnostics(t.Context(), spec().Name, dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "runner.log"))
	if err != nil || string(data) != "fixture diagnostic" {
		t.Fatal("diagnostics parsing changed", err)
	}
	a.response = func([]string, []byte) (byte, []byte) { return 'O', []byte("private invalid archive") }
	if err := adopted.CollectDiagnostics(t.Context(), spec().Name, dir); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("invalid archive accepted or leaked")
	}
}

func TestAgentReadinessCancellationBoundsProof(t *testing.T) {
	p, a := usePipeAgent(t)
	release := make(chan struct{})
	defer close(release)
	a.response = func([]string, []byte) (byte, []byte) { <-release; return 'O', nil }
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	report, err := p.waitReady(ctx, spec().Name)
	if !errors.Is(err, provider.GuestAgentTimeout) || !errors.Is(err, context.DeadlineExceeded) || report.FailureStep != "agent_proof" {
		t.Fatal("readiness proof escaped caller bound", err)
	}
}
func TestAgentUncertainMutationsAreNotReplayed(t *testing.T) {
	for _, mode := range []string{"seed-jit", "start"} {
		t.Run(mode, func(t *testing.T) {
			p, a := usePipeAgent(t)
			a.response = func(argv []string, _ []byte) (byte, []byte) {
				if argv[len(argv)-1] == mode {
					return 'C', nil
				} // Close without an exit frame.
				return 'O', nil
			}
			if err := p.StartRunner(t.Context(), spec().Name, []byte("fixture-jit")); !errors.Is(err, provider.GuestAgentUnavailable) {
				t.Fatal("uncertain mutation failure lost", err)
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			count := 0
			for _, argv := range a.requests {
				if argv[len(argv)-1] == mode {
					count++
				}
			}
			if count != 1 {
				t.Fatal("uncertain mutation was replayed")
			}
		})
	}
}
