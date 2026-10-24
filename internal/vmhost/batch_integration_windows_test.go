//go:build windows && integration

package vmhost

// TestLabBatch boots disposable guests from an existing prepared image through
// this package, the HvSocket transport and the guest client, and records
// bounded numeric results. It is excluded from default tests: it needs the
// integration tag, explicit elevation and lab flags. It never touches another
// compute system or any production state.
//
// Runs, each a fresh cold boot from a new differencing disk:
//   1. Baseline (2 CPU, 4 GiB): agent and desktop rendering; plus an
//      unelevated child refused the ungranted agent service; lazy-memory grants it
//      and verifies that the same manager account connects.
//   2. Lazily committed (virtual-address-backed) memory with GPU-PV.
//   3. A guest whose parent is a flattened single-file copy of the image.
//   4-5. Production sizing (4 CPU, 8 GiB), twice.
//   6. Opt-in failed start (2 CPU, 2 GiB lazy memory, no GPU, a missing
//      second disk).

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/hcs"
	"github.com/GomerPiles/bivouac/internal/hvsock"
	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/windesktop"
	"golang.org/x/sys/windows"
)

var lab = struct {
	root, flattenDir, results, image, imageSHA256, guestName, guestUser *string
	probeSHA256, validationSHA256, autologonSHA256, dial, only          *string
}{
	only:             flag.String("lab.only", "", "comma-separated run labels to run; five default runs when empty; failed-start is opt-in"),
	root:             flag.String("lab.root", "", "new or empty administrator-protected VM host directory"),
	flattenDir:       flag.String("lab.flatten-dir", "", "new or empty directory for the flattened image"),
	results:          flag.String("lab.results", "", "new results file (JSON lines)"),
	image:            flag.String("lab.image", "", "prepared image VHDX"),
	imageSHA256:      flag.String("lab.image-sha256", "", "prepared image SHA-256"),
	guestName:        flag.String("lab.guest-name", "", "prepared image's Windows computer name"),
	guestUser:        flag.String("lab.guest-user", "", "prepared image's console user"),
	probeSHA256:      flag.String("lab.probe-sha256", "", "prepared image's render probe SHA-256"),
	validationSHA256: flag.String("lab.validation-sha256", "", "prepared image's validation script SHA-256"),
	autologonSHA256:  flag.String("lab.autologon-sha256", "", "prepared image's autologon helper SHA-256"),
	dial:             flag.String("lab.dial", "", "internal: unelevated child dial target vmid/service"),
}

// The prepared image's own validation script is pinned by hash in the image.
// These fixed entries reach it exactly as the image's builder did: a small
// framed stdin request whose entry checks the script hash before running it.
const (
	validateBootstrap = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);function Write-SpikeStep([int]$s){[Console]::Out.WriteLine('BIVOUAC_HCS_STEP:'+$s);if($p.data.require_setup -eq $true){try{[IO.File]::WriteAllText(('C:\ProgramData\Bivouac\Image\hcs-spike-validation-step.json'),('{"step":'+$s+'}'))}catch{}}};function Read-SpikeBytes([int]$n){$b=New-Object byte[] $n;$o=0;while($o -lt $n){$r=$i.Read($b,$o,[Math]::Min(4096,$n-$o));if($r -le 0){throw 'frame'};$o+=$r};return ,$b};try{Write-SpikeStep 1;$i=[Console]::OpenStandardInput();$n=[BitConverter]::ToUInt32((Read-SpikeBytes 4),0);if(!$n -or $n -gt 65536){exit 18};Write-SpikeStep 4;$b=Read-SpikeBytes $n;Write-SpikeStep 2;$p=[Text.Encoding]::UTF8.GetString($b)|ConvertFrom-Json;Write-SpikeStep 3;$global:LASTEXITCODE=0;$null = & ([ScriptBlock]::Create($p.script)) $p.data 1>$null 3>$null 4>$null 5>$null 6>$null;exit [int]$global:LASTEXITCODE}catch{exit 18}`
	validateEntry     = `param($data);$f=Join-Path 'C:\ProgramData\Bivouac\Image' 'hcs-spike-validate.ps1';if((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ine $data.script_sha256){exit 14};& $f $data`
)

func encodedPowerShell(s string) string {
	words := windows.StringToUTF16(s)
	b := make([]byte, 0, len(words)*2)
	for _, w := range words[:len(words)-1] {
		b = binary.LittleEndian.AppendUint16(b, w)
	}
	return base64.StdEncoding.EncodeToString(b)
}

type labRun struct {
	AgentLive     *agentLiveFacts  `json:"agent_live,omitempty"`
	Run           string           `json:"run"`
	Name          string           `json:"name"`
	CPU           uint32           `json:"cpu"`
	MemoryMB      uint64           `json:"memory_mb"`
	LazyMemory    bool             `json:"lazy_memory"`
	Flattened     bool             `json:"flattened"`
	Passed        bool             `json:"passed"`
	Failure       string           `json:"failure,omitempty"`
	Timings       map[string]int64 `json:"timings_ms"`
	DialAttempts  int              `json:"agent_dial_attempts"`
	DialLongestMS int64            `json:"agent_dial_longest_ms"`

	Render      *render           `json:"render,omitempty"`
	Steps       map[string]int64  `json:"validation_steps_ms,omitempty"`
	Memory      map[string]uint64 `json:"host_memory_mb,omitempty"`
	Unelevated  map[string]string `json:"unelevated,omitempty"`
	Cleaned     bool              `json:"cleaned"`
	FailedStart *failedStart      `json:"failed_start,omitempty"`
}

type failedStart struct {
	HostCPU         int               `json:"host_cpu"`
	CreateSucceeded bool              `json:"create_succeeded"`
	CreateError     string            `json:"create_error"`
	Retained        bool              `json:"retained"`
	HCSError        bool              `json:"hcs_error"`
	HCSOp           string            `json:"hcs_op,omitempty"`
	HCSCode         string            `json:"hcs_code,omitempty"`
	JournalEmpty    bool              `json:"journal_empty"`
	NativeAbsent    bool              `json:"native_absent"`
	JournalError    string            `json:"journal_error,omitempty"`
	OpenError       string            `json:"open_error,omitempty"`
	DestroyError    string            `json:"destroy_error,omitempty"`
	Calls           []failedStartCall `json:"calls"`
}

type failedStartCall struct {
	Handle     string                 `json:"handle"`
	Op         string                 `json:"op"`
	Properties *failedStartProperties `json:"properties,omitempty"`
	Error      string                 `json:"error"`
}

type failedStartProperties struct {
	IDMatches    bool   `json:"id_matches"`
	OwnerMatches bool   `json:"owner_matches"`
	SystemType   string `json:"system_type"`
	State        string `json:"state"`
	RuntimeIDSet bool   `json:"runtime_id_set"`
}

type failedStartNative struct {
	native
	name, owner string
	result      *failedStart
}

// Create adds a second disk whose file does not exist. HCS accepts the
// document and fails only at start, when the VM worker opens its disks;
// excess vCPUs are refused at create instead.
func (n *failedStartNative) Create(ctx context.Context, name string, doc hcs.ComputeSystem) (system, error) {
	vm := *doc.VirtualMachine
	primary := vm.Devices.Scsi["Primary"]
	attachments := maps.Clone(primary.Attachments)
	attachments["1"] = hcs.Attachment{Type: hcs.AttachmentVirtualDisk, Path: filepath.Join(filepath.Dir(attachments["0"].Path), "missing.vhdx")}
	vm.Devices.Scsi = maps.Clone(vm.Devices.Scsi)
	vm.Devices.Scsi["Primary"] = hcs.Scsi{Attachments: attachments}
	doc.VirtualMachine = &vm
	s, err := n.native.Create(ctx, name, doc)
	if s != nil {
		s = &failedStartSystem{system: s, recorder: n, handle: "create"}
	}
	return s, err
}

func (n *failedStartNative) Open(ctx context.Context, name string) (system, error) {
	s, err := n.native.Open(ctx, name)
	if s != nil {
		s = &failedStartSystem{system: s, recorder: n, handle: "open"}
	}
	return s, err
}

type failedStartSystem struct {
	system
	recorder *failedStartNative
	handle   string
}

func (s *failedStartSystem) Properties(ctx context.Context) (hcs.Properties, error) {
	p, err := s.system.Properties(ctx)
	s.recorder.result.Calls = append(s.recorder.result.Calls, failedStartCall{
		Handle: s.handle, Op: "properties", Error: labError(err),
		Properties: &failedStartProperties{
			IDMatches: p.ID == s.recorder.name, OwnerMatches: p.Owner == s.recorder.owner,
			SystemType: p.SystemType, State: p.State, RuntimeIDSet: p.RuntimeID != "",
		},
	})
	return p, err
}

func (s *failedStartSystem) Start(ctx context.Context) error {
	err := s.system.Start(ctx)
	s.recorder.result.Calls = append(s.recorder.result.Calls, failedStartCall{Handle: s.handle, Op: "start", Error: labError(err)})
	return err
}

func (s *failedStartSystem) Terminate(ctx context.Context) error {
	err := s.system.Terminate(ctx)
	s.recorder.result.Calls = append(s.recorder.result.Calls, failedStartCall{Handle: s.handle, Op: "terminate", Error: labError(err)})
	return err
}

func labError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type render struct {
	windesktop.Topology
	Boot              map[string]uint64 `json:"boot"`
	CredentialRotated bool              `json:"credential_rotated"`
	GuestReady        bool              `json:"guest_ready"`
	DesktopReady      bool              `json:"desktop_ready"`
	HardwareD3D11     bool              `json:"hardware_d3d11"`
	Presented         bool              `json:"presented"`
	PixelReadback     bool              `json:"pixel_readback"`
	Stage             uint32            `json:"stage"`
	HRESULT           uint32            `json:"hresult"`
	VendorID          uint32            `json:"vendor_id"`
	HardwareAdapters  uint32            `json:"hardware_adapter_count"`
	VirtualRender     uint32            `json:"virtual_render_device_count"`
	VirtualProblem    uint32            `json:"virtual_render_problem_code"`
}

func (r *render) ok() bool {
	return r.GuestReady && r.DesktopReady && r.HardwareD3D11 && r.Presented && r.PixelReadback && r.Stage == 7 && r.HRESULT == 0 && r.HardwareAdapters > 0 && r.CredentialRotated && r.Topology.LabOK()
}

type results struct {
	mu sync.Mutex
	f  *os.File
}

func (r *results) write(t *testing.T, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err = r.f.Write(append(b, '\n')); err == nil {
		err = r.f.Sync()
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestLabBatch(t *testing.T) {
	if *lab.root == "" {
		t.Skip("lab flags not provided")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("lab batch requires an explicitly elevated launch")
	}
	f, err := os.OpenFile(*lab.results, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("results file must be new:", err)
	}
	out := &results{f: f}
	defer func() { _ = f.Close() }()
	status := map[string]any{"event": "start", "at": time.Now().UTC().Format(time.RFC3339)}
	out.write(t, status)
	defer func() {
		out.write(t, map[string]any{"event": "end", "failed": t.Failed(), "at": time.Now().UTC().Format(time.RFC3339)})
	}()

	for _, v := range []string{*lab.imageSHA256, *lab.probeSHA256, *lab.validationSHA256, *lab.autologonSHA256} {
		if b, err := hex.DecodeString(v); err != nil || len(b) != 32 {
			t.Fatal("lab pins must be SHA-256 values")
		}
	}
	for _, dir := range []string{*lab.root, *lab.flattenDir} {
		if err := protectedEmptyDirectory(dir); err != nil {
			t.Fatal(err)
		}
	}
	started := time.Now()
	pin, err := pinImage(*lab.image, *lab.imageSHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(pin) }()
	out.write(t, map[string]any{"event": "image-verified", "ms": time.Since(started).Milliseconds()})

	host, err := Open(*lab.root, "lab-batch")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()

	flattened := filepath.Join(*lab.flattenDir, "prepared-flat.vhdx")
	runs := []struct {
		label      string
		cpu        uint32
		memoryMB   uint64
		lazy       bool
		flatten    bool
		unelevated bool
	}{
		{"baseline", 2, 4096, false, false, true},
		{"lazy-memory", 2, 4096, true, false, true},
		{"flattened", 2, 4096, false, true, false},
		{"production-size-1", 4, 8192, false, false, false},
		{"production-size-2", 4, 8192, false, false, false},
		{"failed-start", 2, 2048, true, false, false},
	}
	for _, run := range runs {
		if *lab.only == "" && run.label == "failed-start" {
			continue
		}
		if *lab.only != "" && !slices.Contains(strings.Split(*lab.only, ","), run.label) {
			continue
		}
		image := *lab.image
		if run.flatten {
			started := time.Now()
			if err := Flatten(*lab.image, flattened); err != nil {
				out.write(t, labRun{Run: run.label, Failure: err.Error()})
				t.Error(err)
				continue
			}
			info, err := os.Stat(flattened)
			if err != nil {
				t.Fatal(err)
			}
			out.write(t, map[string]any{"event": "flattened", "ms": time.Since(started).Milliseconds(), "bytes": info.Size()})
			image = flattened
		}
		if err := waitForReserves(t, run.memoryMB, out); err != nil {
			out.write(t, labRun{Run: run.label, Failure: err.Error()})
			t.Error(err)
			break
		}
		var r labRun
		if run.label == "failed-start" {
			r = failStartAndValidate(t, host, image)
		} else {
			r = bootAndValidate(t, host, image, sid, run.label, run.cpu, run.memoryMB, run.lazy, run.unelevated)
		}
		r.Flattened = run.flatten
		out.write(t, r)
		if !r.Passed {
			t.Errorf("%s: %s", run.label, r.Failure)
		}
		if !r.Cleaned {
			t.Error("guest storage retained; stopping the batch")
			break
		}
	}
	if err := host.Recover(context.Background()); err != nil {
		t.Error("retained guests after batch:", err)
	}
	if err := os.Remove(flattened); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Error("cannot remove flattened image:", err)
	}
}

func failStartAndValidate(t *testing.T, host *Host, image string) (r labRun) {
	r = labRun{Run: "failed-start", CPU: 2, MemoryMB: 2048, LazyMemory: true, Timings: map[string]int64{}}
	r.FailedStart = &failedStart{HostCPU: runtime.NumCPU(), Calls: []failedStartCall{}}
	f := r.FailedStart
	var id [5]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	r.Name = "bivouac-lab-" + hex.EncodeToString(id[:])
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	watch := watchReserves(ctx, cancel)
	defer watch()
	original := host.native
	host.native = &failedStartNative{native: original, name: r.Name, owner: host.owner, result: f}
	defer func() { host.native = original }()
	started := time.Now()
	g, err := host.Create(ctx, Spec{
		Name: r.Name, Image: image, CPU: r.CPU, MemoryMB: r.MemoryMB, LazyMemory: true, GPU: false,
		Services: []Service{{ID: guestagent.ServiceID}},
	})
	r.Timings["create_total"] = time.Since(started).Milliseconds()
	host.native = original
	f.CreateSucceeded, f.CreateError, f.Retained = err == nil, labError(err), errors.Is(err, errRetained)
	var nativeErr *hcs.Error
	f.HCSError = errors.As(err, &nativeErr)
	if f.HCSError {
		f.HCSOp, f.HCSCode = nativeErr.Op, fmt.Sprintf("0x%08x", nativeErr.Code)
	}
	cleanCtx, done := context.WithTimeout(context.Background(), 2*time.Minute)
	defer done()
	if err == nil {
		r.Failure = "create unexpectedly succeeded; forcing condition did not hold"
		started := time.Now()
		f.DestroyError = labError(host.Destroy(cleanCtx, g))
		r.Timings["destroy"] = time.Since(started).Milliseconds()
	}
	entries, journalErr := fs.ReadDir(host.root.FS(), ".")
	f.JournalError = labError(journalErr)
	f.JournalEmpty = journalErr == nil
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), r.Name) {
			f.JournalEmpty = false
		}
	}
	s, openErr := host.native.Open(cleanCtx, r.Name)
	if s != nil {
		s.Close()
	}
	f.NativeAbsent = errors.Is(openErr, hcs.ErrNotFound)
	if !f.NativeAbsent {
		f.OpenError = labError(openErr)
	}
	r.Cleaned = f.JournalEmpty && f.NativeAbsent
	r.Passed = err != nil && !f.Retained && r.Cleaned
	if !r.Passed && r.Failure == "" {
		r.Failure = "failed create retained its guest or storage, or cleanup could not be confirmed"
	}
	return r
}

func TestLabFailedStartRecording(t *testing.T) {
	for _, mode := range []string{"owner", "properties", "storage", "success"} {
		t.Run(mode, func(t *testing.T) {
			h, n := fixture(t)
			n.terminateOnClose = true
			if mode != "success" {
				n.startErr = &hcs.Error{Op: "HcsStartComputeSystem", Code: 0x8007139f}
			}
			n.afterFailedStart = func(p *hcs.Properties) {
				switch mode {
				case "owner":
					p.Owner = ""
				case "properties":
					n.propertiesErr = errors.New("properties unavailable")
				case "storage":
					if err := os.WriteFile(filepath.Join(h.dir, n.created[0], "unexpected"), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			r := failStartAndValidate(t, h, validSpec().Image)
			f := r.FailedStart
			if h.native != n || !f.NativeAbsent || len(n.systems) != 0 {
				t.Fatal("native API was not restored or guest remains")
			}
			if r.Passed != (mode == "owner" || mode == "properties") || r.Cleaned != (mode != "storage") || f.Retained != (mode == "storage") {
				t.Fatal("incorrect failure or cleanup outcome")
			}
			if f.CreateSucceeded != (mode == "success") || f.HCSError != (mode != "success") || f.HostCPU != runtime.NumCPU() {
				t.Fatal("missing create outcome or host CPU count")
			}
			if mode != "success" && (f.HCSOp != "HcsStartComputeSystem" || f.HCSCode != "0x8007139f" || f.CreateError == "") {
				t.Fatal("missing HCS failure detail")
			}
			if len(f.Calls) < 3 || f.Calls[0].Op != "properties" || f.Calls[1].Op != "start" || f.Calls[2].Op != "properties" || f.Calls[0].Handle != "create" {
				t.Fatal("missing ordered create-handle observations")
			}
			if mode == "owner" && f.Calls[2].Properties.OwnerMatches {
				t.Fatal("ownership loss was not recorded")
			}
			if mode == "properties" && f.Calls[2].Error != "properties unavailable" {
				t.Fatal("property error was not recorded")
			}
			b, err := json.Marshal(r)
			if err != nil || strings.Contains(string(b), fakeRuntimeID) || strings.Contains(string(b), h.owner) {
				t.Fatal("result encoding failed or disclosed native identity")
			}
		})
	}
}

func TestLabFailedStartRecordsOpenedHandle(t *testing.T) {
	h, n := fixture(t)
	g, err := h.Create(t.Context(), validSpec())
	if err != nil {
		t.Fatal(err)
	}
	f := &failedStart{}
	recorder := &failedStartNative{native: n, name: g.Name, owner: h.owner, result: f}
	s, err := recorder.Open(t.Context(), g.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Properties(t.Context()); err != nil {
		t.Fatal(err)
	}
	terminateErr := &hcs.Error{Op: "HcsTerminateComputeSystem", Code: 0x8007139f}
	n.terminateErr = terminateErr
	if err := s.Terminate(t.Context()); !errors.Is(err, n.terminateErr) {
		t.Fatal("terminate error was not delegated")
	}
	n.terminateErr = nil
	if err := s.Terminate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(f.Calls) != 3 || f.Calls[0].Handle != "open" || !f.Calls[0].Properties.RuntimeIDSet || f.Calls[1].Op != "terminate" || f.Calls[1].Error != terminateErr.Error() || f.Calls[2].Error != "" {
		t.Fatal("missing ordered open-handle observations")
	}
	if err := h.Destroy(t.Context(), g); err != nil {
		t.Fatal(err)
	}
}

// bootAndValidate creates one guest and proves agent and rendering.
// Cleanup runs regardless of failure and must confirm native absence.
func bootAndValidate(t *testing.T, host *Host, image, sid, label string, cpu uint32, memoryMB uint64, lazy, unelevated bool) (r labRun) {
	r = labRun{Run: label, CPU: cpu, MemoryMB: memoryMB, LazyMemory: lazy, Timings: map[string]int64{}, Memory: map[string]uint64{}}
	var id [5]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	r.Name = "bivouac-lab-" + hex.EncodeToString(id[:])
	sampleMemory(r.Memory, "before")
	services := []Service{{ID: guestagent.ServiceID}}
	if unelevated {
		if label != "baseline" {
			services[0].Connect = []string{sid}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	watch := watchReserves(ctx, cancel)
	defer watch()
	started := time.Now()
	g, err := host.Create(ctx, Spec{Name: r.Name, Image: image, CPU: cpu, MemoryMB: memoryMB, LazyMemory: lazy, GPU: true, Services: services})
	if err != nil {
		r.Failure = "create: " + err.Error()
		r.Cleaned = host.Recover(context.Background()) == nil
		return r
	}
	ms := func(d time.Duration) int64 { return d.Milliseconds() }
	r.Timings["disk"], r.Timings["state_files"], r.Timings["grants"] = ms(g.Timings.Disk), ms(g.Timings.StateFiles), ms(g.Timings.Grants)
	r.Timings["create"], r.Timings["start"], r.Timings["gpu"] = ms(g.Timings.Create), ms(g.Timings.Start), ms(g.Timings.GPU)
	r.Timings["create_total"] = ms(time.Since(started))
	sampleMemory(r.Memory, "after_start")
	defer func() {
		cleanup := time.Now()
		cleanCtx, done := context.WithTimeout(context.Background(), 2*time.Minute)
		defer done()
		err := host.Destroy(cleanCtx, g)
		r.Timings["destroy"] = ms(time.Since(cleanup))
		r.Cleaned = err == nil
		if err != nil && r.Failure == "" {
			r.Failure = "destroy: " + err.Error()
		}
	}()
	fail := func(stage string, err error) labRun {
		r.Failure = stage + ": " + err.Error()
		return r
	}
	dialStarted := time.Now()
	var connectedAt time.Time
	dial := guestagent.DialHvsockMeasured(g.RuntimeID, func(elapsed time.Duration, _ bool) {
		r.DialAttempts++
		r.DialLongestMS = max(r.DialLongestMS, ms(elapsed))
	})
	observed := func(ctx context.Context) (net.Conn, error) {
		if err := host.Running(ctx, g); err != nil {
			return nil, errors.New("guest running proof failed")
		}
		conn, err := dial(ctx)
		if err == nil && conn != nil && connectedAt.IsZero() {
			connectedAt = time.Now()
			r.Timings["agent_connect"] = ms(connectedAt.Sub(dialStarted))
		}
		return conn, err
	}
	if err := proveLabAgent(ctx, observed); err != nil {
		return fail("agent proof", err)
	}
	r.Timings["agent_init"] = ms(time.Since(connectedAt))
	r.Timings["agent_reachable"] = ms(time.Since(started))
	if unelevated {
		key := "ungranted_agent"
		if label != "baseline" {
			key = "granted_agent"
		}
		r.Unelevated = map[string]string{key: unelevatedDial(t, g.RuntimeID, guestagent.ServiceID)}
	}
	validationStarted := time.Now()
	report, steps, err := validateDesktop(ctx, observed)
	r.Timings["desktop_validation"] = ms(time.Since(validationStarted))
	r.Steps = steps
	r.Render = report
	if err != nil {
		return fail("desktop validation", err)
	}
	if !report.ok() {
		return fail("desktop validation", errors.New("rendering or single-display input checks did not all pass"))
	}
	r.Timings["to_validated_desktop"] = ms(time.Since(started))
	liveStarted := time.Now()
	facts, err := agentLiveChecks(ctx, observed)
	r.AgentLive = &facts
	r.Timings["agent_live_gates"] = ms(time.Since(liveStarted))
	if err != nil {
		return fail("agent live gates", err)
	}
	sampleMemory(r.Memory, "after_validation")
	r.Passed = authorizationOK(r.Unelevated)
	if !r.Passed {
		r.Failure = "unelevated HvSocket access did not follow the service table"
	}
	return r
}

// Prove protocol compatibility before validation, retrying only harmless proof.
func proveLabAgent(ctx context.Context, dial guestagent.Dialer) error {
	for {
		attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := guestagent.Run(attempt, dial, []string{guestagent.WindowsPath, "version"}, nil, io.Discard)
		cancel()
		if err == nil {
			return nil
		}
		var version *guestagent.VersionError
		if errors.As(err, &version) {
			return errors.New("agent protocol mismatch")
		}
		select {
		case <-ctx.Done():
			return errors.New("agent proof unavailable")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func authorizationOK(results map[string]string) bool {
	if results == nil {
		return true
	}
	if len(results) != 1 {
		return false
	}
	return results["granted_agent"] == "connected" || results["ungranted_agent"] == "access-denied"
}

// validateDesktop runs the image's pinned script. Fixed numeric markers and the
// JSON report share bounded stdout; the client discards guest stderr.
func validateDesktop(ctx context.Context, dial guestagent.Dialer) (*render, map[string]int64, error) {
	payload, err := json.Marshal(map[string]any{"script": validateEntry, "data": map[string]any{
		"name": *lab.guestName, "user": *lab.guestUser, "sha256": *lab.probeSHA256, "script_sha256": *lab.validationSHA256,
		"require_setup": false, "prepared": true, "autologon_sha256": *lab.autologonSHA256,
	}})
	if err != nil {
		return nil, nil, err
	}
	framed := binary.LittleEndian.AppendUint32(nil, uint32(len(payload))) // #nosec G115 -- fixed bounded request.
	framed = append(framed, payload...)
	vctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	output := &validationOutput{steps: map[string]int64{}, begun: time.Now()}
	err = guestagent.Run(vctx, dial, []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedPowerShell(validateBootstrap)}, bytes.NewReader(framed), output)
	if err != nil {
		var exit *guestagent.ExitError
		if errors.As(err, &exit) && exit.Code > 0 && exit.Code <= 255 {
			return nil, output.steps, fmt.Errorf("validation exited with step %d", exit.Code)
		}
		return nil, output.steps, errors.New("validation transport failed")
	}
	var report render
	if json.Unmarshal(output.pending, &report) != nil {
		return nil, output.steps, errors.New("invalid bounded validation report")
	}
	return &report, output.steps, nil
}

// Fixed numeric markers share bounded stdout with the final JSON. Guest stderr
// is discarded by the agent client, so it can never enter lab reports.
type validationOutput struct {
	pending []byte
	total   int
	steps   map[string]int64
	begun   time.Time
}

func (b *validationOutput) Write(p []byte) (int, error) {
	b.total += len(p)
	if b.total > 8192 {
		return 0, errors.New("validation output exceeds bound")
	}
	b.pending = append(b.pending, p...)
	for {
		line, rest, found := bytes.Cut(b.pending, []byte{'\n'})
		if !found {
			break
		}
		step, ok := strings.CutPrefix(strings.TrimSuffix(string(line), "\r"), "BIVOUAC_HCS_STEP:")
		n, err := strconv.Atoi(step)
		if !ok || err != nil || n < 1 || n >= 100 {
			break
		}
		b.steps[strconv.Itoa(n)] = time.Since(b.begun).Milliseconds()
		b.pending = rest
	}
	return len(p), nil
}

// unelevatedDial reruns this test binary as a child of the user's unelevated
// Explorer, so it inherits that token, and reports how its dial ended.
func unelevatedDial(t *testing.T, runtimeID, service string) string {
	parent, err := unelevatedParent()
	if err != nil {
		return "no-unelevated-parent"
	}
	defer func() { _ = windows.CloseHandle(parent) }()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestLabUnelevatedDial$", "-lab.dial="+runtimeID+"/"+service)
	cmd.SysProcAttr = &syscall.SysProcAttr{ParentProcess: syscall.Handle(parent), CreationFlags: windows.CREATE_NO_WINDOW}
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return "connected"
	case errors.As(err, &exit) && exit.ExitCode() == 3:
		return "access-denied"
	case errors.As(err, &exit) && exit.ExitCode() == 4:
		return "refused-or-unreachable"
	case errors.As(err, &exit) && exit.ExitCode() == 5:
		return "child-was-elevated"
	case errors.As(err, &exit):
		return "exit-" + strconv.Itoa(exit.ExitCode())
	default:
		return "launch-failed"
	}
}

func unelevatedParent() (windows.Handle, error) {
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return 0, err
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if !strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), "explorer.exe") {
			continue
		}
		process, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS|windows.PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
		if err != nil {
			continue
		}
		var token windows.Token
		if windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token) == nil {
			user, userErr := token.GetTokenUser()
			elevated := token.IsElevated()
			_ = token.Close()
			if userErr == nil && windows.EqualSid(user.User.Sid, me.User.Sid) && !elevated {
				return process, nil
			}
		}
		_ = windows.CloseHandle(process)
	}
	return 0, errors.New("no unelevated Explorer for this user")
}

// TestLabUnelevatedDial is the child half of unelevatedDial. Exit codes:
// 0 reached the service, 3 access denied, 4 refused or unreachable, 5 elevated.
func TestLabUnelevatedDial(t *testing.T) {
	if *lab.dial == "" {
		t.Skip("child process only")
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		os.Exit(5)
	}
	os.Exit(childDial(*lab.dial))
}

func childDial(target string) int {
	vm, service, _ := strings.Cut(target, "/")
	vmID, err1 := hvsock.ParseGUID(vm)
	serviceID, err2 := hvsock.ParseGUID(service)
	if err1 != nil || err2 != nil {
		return 6
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := hvsock.Dial(ctx, hvsock.Addr{VMID: vmID, ServiceID: serviceID})
	if errors.Is(err, windows.WSAEACCES) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return 3
	}
	if err != nil {
		return 4
	}
	_ = conn.Close()
	return 0
}

// pinImage holds a handle that denies writers and deletion for the whole
// batch, then verifies the image hash through a second read-only handle. The
// pin is never wrapped in an os.File, whose finalizer could close it.
func pinImage(path, sha string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return 0, fmt.Errorf("cannot pin image: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		_ = windows.CloseHandle(h)
		return 0, err
	}
	defer func() { _ = f.Close() }()
	sum := sha256.New()
	if _, err = io.Copy(sum, f); err != nil || !strings.EqualFold(hex.EncodeToString(sum.Sum(nil)), sha) {
		_ = windows.CloseHandle(h)
		return 0, errors.New("prepared image SHA-256 differs")
	}
	return h, nil
}

// protectedEmptyDirectory creates dir with an administrator-only owner and
// DACL (VM workers may read) or accepts it only if it is protected and empty.
func protectedEmptyDirectory(dir string) error {
	if !localAbsolute(dir) {
		return errors.New("lab directories must be local absolute paths")
	}
	if err := os.Mkdir(dir, 0o700); err == nil {
		sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-83-0)")
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		acl, _, err := sd.DACL()
		if err != nil {
			return err
		}
		if err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() != "daemon.lock" {
			return fmt.Errorf("lab directory %s is not empty", dir)
		}
	}
	return nil
}

func sampleMemory(into map[string]uint64, label string) {
	s, err := perf.NewSampler(*lab.root).Sample()
	if err != nil {
		return
	}
	into[label+"_available"] = s.AvailableBytes >> 20
	if s.Commit != nil {
		into[label+"_commit_headroom"] = s.Commit.HeadroomBytes() >> 20
	}
}

// Before each boot, leave room for production CI to start its own guest:
// physical memory and commit headroom must exceed the guest by 10 GiB and
// 8 GiB for 30 continuous seconds, within 15 minutes.
func waitForReserves(t *testing.T, guestMB uint64, out *results) error {
	need, needCommit := (guestMB+10<<10)<<20, (guestMB+8<<10)<<20
	deadline := time.Now().Add(15 * time.Minute)
	var since time.Time
	for time.Now().Before(deadline) {
		s, err := perf.NewSampler(*lab.root).Sample()
		if err == nil && s.AvailableBytes >= need && s.Commit != nil && s.Commit.HeadroomBytes() >= needCommit {
			if since.IsZero() {
				since = time.Now()
			}
			if time.Since(since) >= 30*time.Second {
				return nil
			}
		} else {
			since = time.Time{}
		}
		time.Sleep(2 * time.Second)
	}
	out.write(t, map[string]any{"event": "reserves-unavailable", "guest_mb": guestMB})
	return errors.New("host reserves unavailable; no guest started")
}

// watchReserves cancels only this run if the host drops below 6 GiB available
// memory or 2 GiB commit headroom, or counters become unavailable.
func watchReserves(ctx context.Context, cancel context.CancelFunc) func() {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				s, err := perf.NewSampler(*lab.root).Sample()
				if err != nil || s.AvailableBytes < 6<<30 || s.Commit == nil || s.Commit.HeadroomBytes() < 2<<30 {
					cancel()
					return
				}
			}
		}
	}()
	return func() { close(done); wg.Wait() }
}
