//go:build windows && integration

package vmhost

// TestLabBatch boots disposable guests from an existing prepared image through
// this package, the HvSocket transport and the guest client, and records
// bounded numeric results. It is excluded from default tests: it needs the
// integration tag, explicit elevation and lab flags. It never touches another
// compute system, the App Sandbox broker or any production state.
//
// Runs, each a fresh cold boot from a new differencing disk:
//   1. Baseline (2 CPU, 4 GiB): agent, SSH, desktop rendering; plus an
//      unelevated child that must reach the SSH service its account was granted
//      and be refused by the agent service it was not.
//   2. Lazily committed (virtual-address-backed) memory with GPU-PV.
//   3. A guest whose parent is a flattened single-file copy of the image.
//   4-5. Production sizing (4 CPU, 8 GiB), twice.

import (
	"bufio"
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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/hvsock"
	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/winguest"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

var lab = struct {
	root, flattenDir, results, image, imageSHA256, guestName, guestUser *string
	probeSHA256, validationSHA256, autologonSHA256, dial, only          *string
}{
	only:             flag.String("lab.only", "", "comma-separated run labels to run; all when empty"),
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
	validateBootstrap = `$ErrorActionPreference='Stop';function Write-SpikeStep([int]$s){[Console]::Error.WriteLine('BIVOUAC_HCS_STEP:'+$s);if($p.data.require_setup -eq $true){try{[IO.File]::WriteAllText(($env:SystemRoot+'\AppSandbox\hcs-spike-validation-step.json'),('{"step":'+$s+'}'))}catch{}}};function Read-SpikeBytes([int]$n){$b=New-Object byte[] $n;$o=0;while($o -lt $n){$r=$i.Read($b,$o,[Math]::Min(4096,$n-$o));if($r -le 0){throw 'frame'};$o+=$r};return ,$b};try{Write-SpikeStep 1;$i=[Console]::OpenStandardInput();$n=[BitConverter]::ToUInt32((Read-SpikeBytes 4),0);if(!$n -or $n -gt 100000000){exit 18};Write-SpikeStep 4;$b=Read-SpikeBytes $n;Write-SpikeStep 2;$p=[Text.Encoding]::UTF8.GetString($b)|ConvertFrom-Json;Write-SpikeStep 3;& ([ScriptBlock]::Create($p.script)) $p.data}catch{exit 18}`
	validateEntry     = `param($data);$f=Join-Path $env:SystemRoot 'AppSandbox\hcs-spike-validate.ps1';if((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ine $data.script_sha256){exit 14};& $f $data`
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
	Run           string            `json:"run"`
	Name          string            `json:"name"`
	CPU           uint32            `json:"cpu"`
	MemoryMB      uint64            `json:"memory_mb"`
	LazyMemory    bool              `json:"lazy_memory"`
	Flattened     bool              `json:"flattened"`
	Passed        bool              `json:"passed"`
	Failure       string            `json:"failure,omitempty"`
	Timings       map[string]int64  `json:"timings_ms"`
	DialAttempts  int               `json:"agent_dial_attempts"`
	DialLongestMS int64             `json:"agent_dial_longest_ms"`
	HostKeySHA256 string            `json:"ssh_host_key_sha256,omitempty"`
	Render        *render           `json:"render,omitempty"`
	Steps         map[string]int64  `json:"validation_steps_ms,omitempty"`
	Memory        map[string]uint64 `json:"host_memory_mb,omitempty"`
	Unelevated    map[string]string `json:"unelevated,omitempty"`
	Cleaned       bool              `json:"cleaned"`
}

type render struct {
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
	return r.GuestReady && r.DesktopReady && r.HardwareD3D11 && r.Presented && r.PixelReadback && r.Stage == 7 && r.HRESULT == 0 && r.HardwareAdapters > 0 && r.CredentialRotated
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
		{"lazy-memory", 2, 4096, true, false, false},
		{"flattened", 2, 4096, false, true, false},
		{"production-size-1", 4, 8192, false, false, false},
		{"production-size-2", 4, 8192, false, false, false},
	}
	for _, run := range runs {
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
		r := bootAndValidate(t, host, image, sid, run.label, run.cpu, run.memoryMB, run.lazy, run.unelevated)
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

// bootAndValidate creates one guest and proves agent, SSH and rendering.
// Cleanup runs regardless of failure and must confirm native absence.
func bootAndValidate(t *testing.T, host *Host, image, sid, label string, cpu uint32, memoryMB uint64, lazy, unelevated bool) (r labRun) {
	r = labRun{Run: label, CPU: cpu, MemoryMB: memoryMB, LazyMemory: lazy, Timings: map[string]int64{}, Memory: map[string]uint64{}}
	var id [5]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	r.Name = "bivouac-lab-" + hex.EncodeToString(id[:])
	sampleMemory(r.Memory, "before")
	services := []Service{{ID: winguest.AgentService}, {ID: winguest.SSHService}}
	if unelevated {
		services[1].Connect = []string{sid}
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
	vmID, err := hvsock.ParseGUID(g.RuntimeID)
	if err != nil {
		return fail("runtime id", err)
	}
	serviceID := func(s string) windows.GUID { id, _ := hvsock.ParseGUID(s); return id }
	verify := func() error { return host.Running(ctx, g) }

	identity, err := winguest.NewIdentity()
	if err != nil {
		return fail("identity", err)
	}
	defer identity.Clear()
	dialStarted := time.Now()
	var agent net.Conn
	for agent == nil {
		if err = verify(); err != nil {
			return fail("agent wait", err)
		}
		r.DialAttempts++
		attempt := time.Now()
		dialCtx, done := context.WithTimeout(ctx, 3*time.Second)
		agent, err = hvsock.Dial(dialCtx, hvsock.Addr{VMID: vmID, ServiceID: serviceID(winguest.AgentService)})
		done()
		r.DialLongestMS = max(r.DialLongestMS, ms(time.Since(attempt)))
		if agent == nil {
			select {
			case <-ctx.Done():
				return fail("agent wait", errors.Join(ctx.Err(), err))
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
	r.Timings["agent_connect"] = ms(time.Since(dialStarted))
	initStarted := time.Now()
	initCtx, done := context.WithTimeout(ctx, 2*time.Minute)
	a, err := winguest.Initialize(initCtx, agent, identity.PublicKey)
	done()
	// Keep the agent session for the guest's life, as the image's builder did.
	defer func() { _ = agent.Close() }()
	r.Timings["agent_init"] = ms(time.Since(initStarted))
	if err != nil || !a.DisplayReady || !a.KeyDeployed {
		return fail("agent init", errors.Join(err, errors.New("display or key not confirmed")))
	}
	if unelevated {
		r.Unelevated = map[string]string{
			"granted_ssh":     unelevatedDial(t, g.RuntimeID, winguest.SSHService),
			"ungranted_agent": unelevatedDial(t, g.RuntimeID, winguest.AgentService),
		}
	}
	sshStarted := time.Now()
	sshCtx, done := context.WithTimeout(ctx, time.Minute)
	transport, err := hvsock.Dial(sshCtx, hvsock.Addr{VMID: vmID, ServiceID: serviceID(winguest.SSHService)})
	if err != nil {
		done()
		return fail("ssh dial", err)
	}
	client, fingerprint, err := winguest.Connect(sshCtx, transport, *lab.guestUser, identity, func(string) error { return verify() })
	done()
	if err != nil {
		_ = transport.Close()
		return fail("ssh", err)
	}
	defer func() { _ = client.Close() }()
	r.HostKeySHA256 = fingerprint
	r.Timings["ssh_auth"] = ms(time.Since(sshStarted))
	validationStarted := time.Now()
	report, steps, err := validateDesktop(ctx, client)
	r.Timings["desktop_validation"] = ms(time.Since(validationStarted))
	r.Steps = steps
	r.Render = report
	if err != nil {
		return fail("desktop validation", err)
	}
	if !report.ok() {
		return fail("desktop validation", errors.New("rendering checks did not all pass"))
	}
	r.Timings["to_validated_desktop"] = ms(time.Since(started))
	sampleMemory(r.Memory, "after_validation")
	r.Passed = r.Unelevated == nil || (r.Unelevated["granted_ssh"] == "connected" && r.Unelevated["ungranted_agent"] == "access-denied")
	if !r.Passed {
		r.Failure = "unelevated HvSocket access did not follow the service table"
	}
	return r
}

// validateDesktop runs the image's pinned validation script. Only fixed numeric
// step markers are read from stderr, and only the bounded JSON report from stdout.
func validateDesktop(ctx context.Context, client *ssh.Client) (*render, map[string]int64, error) {
	payload, err := json.Marshal(map[string]any{"script": validateEntry, "data": map[string]any{
		"name": *lab.guestName, "user": *lab.guestUser, "sha256": *lab.probeSHA256, "script_sha256": *lab.validationSHA256,
		"require_setup": false, "prepared": true, "autologon_sha256": *lab.autologonSHA256,
	}})
	if err != nil {
		return nil, nil, err
	}
	framed := binary.LittleEndian.AppendUint32(nil, uint32(len(payload))) // #nosec G115 -- a small fixed request.
	framed = append(framed, payload...)
	vctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	stop := context.AfterFunc(vctx, func() { _ = client.Close() })
	defer stop()
	session, err := client.NewSession()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = session.Close() }()
	var stdout strings.Builder
	session.Stdin = strings.NewReader(string(framed))
	session.Stdout = &boundedWriter{w: &stdout, limit: 8192}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	steps := map[string]int64{}
	begun := time.Now()
	var reading sync.WaitGroup
	reading.Add(1)
	go func() {
		defer reading.Done()
		scanner := bufio.NewScanner(io.LimitReader(stderr, 1<<20))
		for scanner.Scan() {
			if step, ok := strings.CutPrefix(scanner.Text(), "BIVOUAC_HCS_STEP:"); ok {
				if n, err := strconv.Atoi(step); err == nil && n > 0 && n < 100 {
					steps[strconv.Itoa(n)] = time.Since(begun).Milliseconds()
				}
			}
		}
		_, _ = io.Copy(io.Discard, stderr)
	}()
	err = session.Run("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encodedPowerShell(validateBootstrap))
	reading.Wait()
	if err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			return nil, steps, fmt.Errorf("validation exited with step %d", exit.ExitStatus())
		}
		return nil, steps, errors.New("validation transport failed")
	}
	var report render
	if err = json.Unmarshal([]byte(stdout.String()), &report); err != nil {
		return nil, steps, errors.New("invalid bounded validation report")
	}
	return &report, steps, nil
}

type boundedWriter struct {
	w     io.Writer
	n     int
	limit int
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	if b.n+len(p) > b.limit {
		return 0, errors.New("validation output exceeds bound")
	}
	b.n += len(p)
	return b.w.Write(p)
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
