//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/hvsock"
	"golang.org/x/sys/windows"
)

type nativeBinding struct {
	NativeID string      `json:"native_id"`
	Probe    nativeFacts `json:"probe"`
}
type correlationReport struct {
	Candidates int             `json:"candidates"`
	Matches    []nativeBinding `json:"matches"`
}

func sandboxOwnerHash() string {
	value := sha256.Sum256([]byte("WindowsSandbox"))
	return hex.EncodeToString(value[:])
}

func (b nativeBinding) matches(record labRecord) bool {
	f := b.Probe
	return record.valid() && record.Phase == "started" && validGUID(record.Boot) && validGUID(b.NativeID) &&
		f.HCS && f.Running && f.IDMatches && f.VM && f.Runtime && f.Agent && f.Session.valid() && validGUID(f.RuntimeID) && f.OwnerHash == sandboxOwnerHash() &&
		f.Identity != nil && f.Identity.valid() && f.Identity.Phase == "started" && f.Identity.ID == record.ID && f.Identity.Name == record.Name && f.Identity.Boot == record.Boot
}

func (r correlationReport) binding(record labRecord) (nativeIdentity, error) {
	if r.Candidates < 1 || r.Candidates > 16 || len(r.Matches) != 1 || !r.Matches[0].matches(record) {
		return nativeIdentity{}, errors.New("unique corroborated native binding required")
	}
	b := r.Matches[0]
	return nativeIdentity{ID: b.NativeID, RuntimeID: b.Probe.RuntimeID, OwnerHash: b.Probe.OwnerHash}, nil
}

func (h *labHost) nativeDial() (guestagent.Dialer, error) {
	if !h.record.valid() || h.record.Native == nil || h.record.Native.OwnerHash != sandboxOwnerHash() {
		return nil, errors.New("recorded native binding required")
	}
	runtimeID := h.record.Native.RuntimeID
	if !validGUID(runtimeID) {
		return nil, errors.New("recorded native runtime required")
	}
	vm, err := hvsock.ParseGUID(runtimeID)
	if err != nil {
		return nil, errors.New("native runtime refused")
	}
	service, _ := hvsock.ParseGUID(serviceID)
	raw := func(ctx context.Context) (net.Conn, error) {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return hvsock.Dial(attempt, hvsock.Addr{VMID: vm, ServiceID: service})
	}
	if h.secure {
		report, err := h.secureReport()
		if err != nil {
			return nil, err
		}
		return secureDial(tcpReport{Fingerprint: report.Fingerprint}, h.client, raw), nil
	}
	return raw, nil
}

func (h *labHost) nativeRun(ctx context.Context, mode string, input io.Reader) ([]byte, error) {
	dial, err := h.nativeDial()
	if err != nil {
		return nil, err
	}
	step, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var output boundedBuffer
	if err := guestagent.Run(step, dial, []string{guestBinary, mode}, input, &output); err != nil {
		return nil, err
	}
	return output.data, nil
}

func (h *labHost) proveNative(ctx context.Context) error {
	data, err := h.nativeRun(ctx, "identity", nil)
	if err != nil {
		return errors.New("native identity channel unavailable")
	}
	var record labRecord
	if decodeBounded(bytes.NewReader(data), &record) != nil || !record.valid() || record.Phase != "started" || record.ID != h.record.ID || record.Name != h.record.Name || record.Boot != h.record.Boot {
		return errors.New("native guest identity differs; retain record")
	}
	return nil
}

// Only discovery runs elevated. The helper can query systems and execute fixed
// public identity probes; it cannot receive commands, JIT input or secrets.
func (h *labHost) discoverNative(ctx context.Context, self string) (nativeIdentity, error) {
	if h.broker != "" {
		candidates, err := brokerCandidates(ctx, h.broker)
		if err != nil {
			return nativeIdentity{}, err
		}
		return h.authenticateCandidates(ctx, candidates)
	}
	root := filepath.Dir(h.input)
	dir := filepath.Join(root, "inspection")
	if os.Mkdir(dir, 0o700) != nil {
		return nativeIdentity{}, errors.New("fresh native inspection directory required")
	}
	helper := filepath.Join(dir, "sandbox-lab.exe")
	if err := copyAsset(self, helper, 512<<20); err != nil {
		return nativeIdentity{}, err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(helper)
	if err != nil {
		return nativeIdentity{}, errors.New("inspection executable refused")
	}
	// ShellExecute's native parameter field requires CRT serialization. This
	// array is escaped by Windows' argv serializer; no shell is invoked.
	mode, filename := "correlate-report", "native-correlation.json"
	if h.secure {
		mode, filename = "candidates-report", "native-candidates.json"
	}
	args, _ := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{mode, filepath.Join(root, "record.json")}))
	cwd, _ := windows.UTF16PtrFromString(dir)
	if err := windows.ShellExecute(0, verb, file, args, cwd, windows.SW_HIDE); err != nil {
		var code windows.Errno
		if errors.As(err, &code) {
			return nativeIdentity{}, fmt.Errorf("native discovery elevation unavailable (code %d)", uint32(code))
		}
		return nativeIdentity{}, errors.New("native discovery elevation unavailable or canceled")
	}
	wait, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	path := filepath.Join(dir, filename)
	if h.secure {
		var candidates []nativeBinding
		for readJSON(path, &candidates) != nil {
			if pause(wait) != nil {
				return nativeIdentity{}, errors.New("native candidates unavailable")
			}
		}
		return h.authenticateCandidates(ctx, candidates)
	}
	var report correlationReport
	for readJSON(path, &report) != nil {
		if pause(wait) != nil {
			return nativeIdentity{}, errors.New("native discovery report unavailable")
		}
	}
	return report.binding(h.record)
}

func (h *labHost) nativeProbe(ctx context.Context, self string, result *labResult) error {
	binding, err := h.discoverNative(ctx, self)
	if err != nil {
		return err
	}
	h.record.Native = &binding
	if err := writeJSON(filepath.Join(filepath.Dir(h.input), "record.json"), h.record); err != nil {
		return err
	}
	if err := h.proveNative(ctx); err != nil {
		return err
	}
	result.Native = true
	result.BrokerDiscovery = h.broker != ""
	data, err := h.nativeRun(ctx, "smoke", strings.NewReader("bivouac-sandbox-stdin-probe"))
	if err != nil {
		return errors.New("native framed smoke failed")
	}
	var smoke smokeFacts
	if decodeBounded(bytes.NewReader(data), &smoke) != nil || !smoke.valid(false) || !smoke.Input {
		return errors.New("native framed smoke predicates failed")
	}
	result.Agent = true
	result.Smoke = &smoke
	if err := h.nativeToolCheck(ctx); err != nil {
		return err
	}
	if h.secure {
		if err := h.authorizationProbes(ctx, self, result); err != nil {
			return err
		}
	}
	data, err = h.nativeRun(ctx, "loopback-probe", nil)
	if err != nil {
		return errors.New("native loopback probe failed")
	}
	var loopback struct {
		Refused bool `json:"refused"`
	}
	if decodeBounded(bytes.NewReader(data), &loopback) != nil || !loopback.Refused {
		return errors.New("guest loopback boundary unproven")
	}
	result.NativeLoopbackRefused = true
	_, err = h.nativeRun(ctx, "expected-failure", nil)
	var exit *guestagent.ExitError
	if !errors.As(err, &exit) || exit.Code != 1 {
		return errors.New("native nonzero-exit propagation failed")
	}
	result.NativeExit = true
	dial, err := h.nativeDial()
	if err != nil {
		return err
	}
	step, cancel := context.WithTimeout(ctx, 2*time.Second)
	var output boundedBuffer
	err = guestagent.Run(step, dial, []string{guestBinary, "wait-probe"}, nil, &output)
	cancel()
	var started struct {
		Started bool `json:"started"`
	}
	if !errors.Is(err, context.DeadlineExceeded) || decodeBounded(bytes.NewReader(output.data), &started) != nil || !started.Started {
		return errors.New("native cancellation probe inconclusive")
	}
	if err := h.proveNative(ctx); err != nil {
		return err
	}
	result.NativeCancellation = true
	// Use the CLI's independent execution context to restart the agent task.
	// An agent command must not try to end its own task and continue running.
	if err := h.prove(ctx); err != nil {
		return err
	}
	data, err = h.call(ctx, "exec", "--id", h.record.ID, "--command", `"C:\Program Files\Bivouac\sandbox-lab.exe" restart-agent`, "--run-as", "ExistingLogin")
	var receipt struct {
		Exit *int `json:"ExitCode"`
	}
	if err != nil || decodeBounded(bytes.NewReader(data), &receipt) != nil || receipt.Exit == nil || *receipt.Exit != 0 {
		return errors.New("agent restart dispatch uncertain")
	}
	var restarted struct {
		Changed bool `json:"changed"`
	}
	if readJSON(filepath.Join(h.output, "restart.json"), &restarted) != nil || !restarted.Changed {
		return errors.New("new agent generation unproven")
	}
	retry, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for h.proveNative(retry) != nil {
		if pause(retry) != nil {
			return errors.New("native reconnect after agent restart failed")
		}
	}
	data, err = h.nativeRun(ctx, "echo", strings.NewReader("bivouac-sandbox-stdin-probe"))
	if err != nil {
		return errors.New("native reconnect stdin failed")
	}
	var echoed struct {
		Input bool `json:"input"`
	}
	if decodeBounded(bytes.NewReader(data), &echoed) != nil || !echoed.Input {
		return errors.New("native reconnect stdin unproven")
	}
	result.NativeRestart = true
	return h.nativeToolCheck(ctx)
}

func loopbackProbe(ctx context.Context, out io.Writer) error {
	if !session().valid() {
		return errors.New("loopback probe session refused")
	}
	service, _ := hvsock.ParseGUID(serviceID)
	step, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := hvsock.Dial(step, hvsock.Addr{VMID: hvsock.LoopbackVMID(), ServiceID: service})
	if conn != nil {
		_ = conn.Close()
	}
	refused := errors.Is(err, windows.WSAEACCES) || errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.WSAECONNREFUSED)
	return json.NewEncoder(out).Encode(struct {
		Refused bool `json:"refused"`
	}{refused})
}

type agentStartup struct {
	sessionFacts
	Generation  string     `json:"generation"`
	Identity    *labRecord `json:"identity,omitempty"`
	Fingerprint string     `json:"fingerprint,omitempty"`
}

func restartAgent(ctx context.Context) error {
	if !session().valid() {
		return errors.New("restart session refused")
	}
	var before agentStartup
	if readJSON(filepath.Join(reportDirectory, "agent.json"), &before) != nil || !validGUID(before.Generation) {
		return errors.New("previous agent generation unavailable")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return errors.New("task control unavailable")
	}
	const script = `$ErrorActionPreference='Stop';Stop-ScheduledTask -TaskName 'bivouac-sandbox-lab-agent';Start-ScheduledTask -TaskName 'bivouac-sandbox-lab-agent'`
	cmd := exec.CommandContext(ctx, filepath.Join(system, `WindowsPowerShell\v1.0\powershell.exe`), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if cmd.Run() != nil {
		return errors.New("guest agent task restart failed")
	}
	wait, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		var after agentStartup
		if readJSON(filepath.Join(reportDirectory, "agent.json"), &after) == nil && after.valid() && validGUID(after.Generation) && after.Generation != before.Generation {
			return writeReport("restart.json", struct {
				Changed bool `json:"changed"`
			}{true})
		}
		if pause(wait) != nil {
			return errors.New("new agent generation unavailable")
		}
	}
}
