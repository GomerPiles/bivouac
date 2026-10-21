//go:build windows

package imagefactory

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestFramedHostResults(t *testing.T) {
	for _, test := range []struct {
		name, text string
		valid      bool
	}{
		{"noise", "formatted disk object\nBIVOUAC_IMAGE_RESULT\n{\"failure_step\":0}\nmore noise", true},
		{"crlf", "noise\r\nBIVOUAC_IMAGE_RESULT\r\n{}\r\n", true},
		{"missing", "{}", false}, {"empty", "BIVOUAC_IMAGE_RESULT\n", false}, {"duplicate", "BIVOUAC_IMAGE_RESULT\n{}\nBIVOUAC_IMAGE_RESULT\n{}", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, err := framedResult([]byte(test.text))
			if (err == nil) != test.valid {
				t.Fatal("frame classification")
			}
			if test.valid && !json.Valid(b) {
				t.Fatal("frame includes noise")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "script.ps1")
	script := "Write-Output 'ignored object';[Console]::Out.WriteLine('BIVOUAC_IMAGE_RESULT');[Console]::Out.WriteLine('{\"failure_step\":62}');exit 62"
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := executeHost(context.Background(), path, nil, true)
	var scriptErr *HostScriptError
	if !errors.As(err, &scriptErr) || scriptErr.Step != 62 || !json.Valid(b) {
		t.Fatal("partial host result/step lost")
	}
	r := &record{}
	r.hostError("inspection", err)
	if r.HostSteps["inspection"] != 62 {
		t.Fatal("step not recorded")
	}
}

// Replace every storage command with a fake. The fake dismount emits an object,
// reproducing the review finding without calling any disk or mount API.
func TestInspectionSinksStorageOutput(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("a", 32)
	workspace := filepath.Join(root, id)
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "disk.vhdx"), []byte("ordinary-test-file"), 0600); err != nil {
		t.Fatal(err)
	}
	marker, _ := json.Marshal(map[string]string{"build_id": id, "workspace": workspace})
	if err := os.WriteFile(filepath.Join(workspace, "owner.json"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	mocks := `
function Add-Type {param($TypeDefinition) [pscustomobject]@{noise='type'}}
function Get-DiskImage {param($ImagePath) [pscustomobject]@{Attached=$false}}
function Mount-DiskImage {param($ImagePath,$Access,[switch]$NoDriveLetter,[switch]$PassThru) if($Access -ne 'ReadWrite'){throw 'access'};[pscustomobject]@{Fake=$true}}
function Get-Disk {[pscustomobject]@{Number=123}}
function Get-Partition {param($DiskNumber) [pscustomobject]@{PartitionNumber=2;Size=100}}
function Add-PartitionAccessPath {param($DiskNumber,$PartitionNumber,$AccessPath)
 $null=New-Item -ItemType Directory -Path (Join-Path $AccessPath 'Windows\Panther\Unattend') -Force
 [IO.File]::WriteAllText((Join-Path $AccessPath 'Windows\Panther\Unattend\setup-step.json'),'{"step":70,"failed":true}')
 [pscustomobject]@{noise='add'}
}

function Remove-PartitionAccessPath {param($DiskNumber,$PartitionNumber,$AccessPath)
 foreach($part in @('Windows\Panther\Unattend\setup-step.json','Windows\Panther\Unattend','Windows\Panther','Windows')){$null=Remove-Item -LiteralPath (Join-Path $AccessPath $part)}
 [pscustomobject]@{noise='remove'}
}
function Dismount-DiskImage {param($ImagePath) [pscustomobject]@{noise='dismount'}}
`
	path := filepath.Join(workspace, "fake-host.ps1")
	if err := os.WriteFile(path, []byte(mocks+runnerCheck+offlineFiles+inspectDisk), 0600); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]string{"root": root, "instance_id": id, "disk": filepath.Join(workspace, "disk.vhdx"), "mode": "setup"})
	b, err := executeHost(context.Background(), path, data, true)
	if err != nil {
		t.Fatal(err)
	}
	var facts Inspection
	if json.Unmarshal(b, &facts) != nil || facts.FailureStep != 0 || facts.GuestSetupStep != 70 || !facts.GuestSetupFailed {
		t.Fatal("inspection JSON contaminated or setup step missing")
	}
}

func TestOfflineHiveBindingsCompile(t *testing.T) {
	start := strings.Index(inspectDisk, "@\"\n") + 3
	if start < 3 {
		t.Fatal("offline bindings missing")
	}
	end := strings.Index(inspectDisk[start:], "\n\"@") + start
	if end < start {
		t.Fatal("offline bindings end missing")
	}
	data, _ := json.Marshal(map[string]string{"code": inspectDisk[start:end]})
	// Compile declarations only. No offreg, registry or disk call is dispatched.
	if runTestPS(t, `$ErrorActionPreference='Stop';$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$null=Add-Type -TypeDefinition $d.code;[Console]::Out.Write('compiled')`, data) != "compiled" {
		t.Fatal("offline binding compile failed")
	}
}

func TestInspectionPreservesPartialFailure(t *testing.T) {
	r := &record{BuildID: strings.Repeat("a", 32), Workspace: `D:\Images\.builds\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`}
	run := func(_ context.Context, script string, data any, output bool) ([]byte, error) {
		if !output || !strings.Contains(script, "Read-FactoryFiles") || data.(map[string]string)["guest_user"] != "imageuser" {
			t.Fatal("wrong inspection path")
		}
		return []byte(`{"failure_step":70,"image_state_kind":"generalized_to_oobe","executables":{"agent.exe":"public-hash"}}`), &HostScriptError{Step: 70}
	}
	facts, err := inspectOwned(context.Background(), testConfig(), r, false, run)
	if facts == nil || facts.FailureStep != 70 || facts.Executables["agent.exe"] != "public-hash" || err == nil {
		t.Fatal("partial inspection facts discarded")
	}
}

func TestGuestSetupFailureStep(t *testing.T) {
	start := strings.Index(guestSetup, "function Write-SetupStep")
	end := strings.Index(guestSetup[start:], "\n}\n") + start + 3
	if start < 0 || end <= start {
		t.Fatal("setup status writer missing")
	}
	// Replace the fixed-path writer and fail at the first service query, before
	// any guest service/install command can execute. No host guest paths are used.
	safeWriter := `function Write-SetupStep([int]$Code,[bool]$Failed){if($Failed){[Console]::Out.WriteLine('BIVOUAC_IMAGE_RESULT');[Console]::Out.WriteLine((@{guest_setup_step=$Code;guest_setup_failed=$Failed}|ConvertTo-Json -Compress))}}
`
	script := "function Get-Service {throw 'fixture failure'}\n" + guestSetup[:start] + safeWriter + guestSetup[end:]
	path := filepath.Join(t.TempDir(), "fake-setup.ps1")
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := executeHost(context.Background(), path, nil, true)
	var scriptErr *HostScriptError
	var facts Inspection
	if !errors.As(err, &scriptErr) || scriptErr.Step != 10 || json.Unmarshal(b, &facts) != nil || facts.GuestSetupStep != 10 || !facts.GuestSetupFailed {
		t.Fatal("setup failure lost numeric step")
	}
}

func TestOfflineFilesystemFacts(t *testing.T) {
	for _, state := range []string{"absent", "unconfigured", "configured", "residue", "incomplete", "invalid", "guest state"} {
		t.Run(state, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"Windows/AppSandbox", "ProgramData/Bivouac/ImagePolicy"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "Windows/AppSandbox/agent.exe"), []byte("public-component"), 0600); err != nil {
				t.Fatal(err)
			}
			if state != "absent" {
				if err := os.MkdirAll(filepath.Join(root, "actions-runner/bin"), 0700); err != nil {
					t.Fatal(err)
				}
				for _, file := range []string{"bin/Runner.Listener.exe", "config.cmd", "run.cmd"} {
					if err := os.WriteFile(filepath.Join(root, "actions-runner", file), []byte("public-component"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if state == "configured" {
				if err := os.WriteFile(filepath.Join(root, "actions-runner/.credentials_future"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if state == "residue" {
				if err := os.MkdirAll(filepath.Join(root, "actions-runner/_work/public-job"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if state == "incomplete" {
				if err := os.Remove(filepath.Join(root, "actions-runner/run.cmd")); err != nil {
					t.Fatal(err)
				}
			}
			if state == "invalid" {
				if err := os.RemoveAll(filepath.Join(root, "actions-runner")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "actions-runner"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if state == "guest state" {
				if err := os.Mkdir(filepath.Join(root, "ProgramData/Bivouac/Guest"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			script := runnerCheck + "\n" + offlineFiles + `;try{$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$f=@{};Read-FactoryFiles $d.root $f;[Console]::Out.Write(($f|ConvertTo-Json -Compress -Depth 5))}catch{[Console]::Out.Write(('{"test_failure_line":'+$_.InvocationInfo.ScriptLineNumber+'}'))}`
			data, _ := json.Marshal(map[string]string{"root": root})
			b := runTestPS(t, script, data)
			var facts Inspection
			var diagnostic struct {
				Line int `json:"test_failure_line"`
			}
			_ = json.Unmarshal([]byte(b), &diagnostic)
			if diagnostic.Line != 0 {
				t.Fatalf("filesystem fixture failed at script line %d", diagnostic.Line)
			}
			if json.Unmarshal([]byte(b), &facts) != nil {
				t.Fatal("filesystem facts JSON")
			}
			want := state
			if state == "guest state" {
				want = "unconfigured"
			}
			if facts.RunnerState != want || facts.GuestStatePresent != (state == "guest state") || !facts.BivouacPresent || facts.Executables["agent.exe"] != hashBytes([]byte("public-component")) {
				t.Fatal("incorrect offline facts")
			}
			if state == "residue" {
				entries := facts.RunnerResidue["_work"].Entries
				if len(entries) != 1 || entries[0].Name != "public-job" || !entries[0].Directory {
					t.Fatal("residue names/types missing")
				}
			}
		})
	}
	if !strings.Contains(imageSanitize, `'C:\ProgramData\Bivouac\Guest'`) || strings.Contains(imageSanitize, `'C:\ProgramData\Bivouac',`) {
		t.Fatal("sanitation rejects image policy state")
	}
	data := []byte(`{"value":"C:\\Program Files\\OpenSSH\\sshd.exe --opaque public-argument.exe"}`)
	result := runTestPS(t, offlineFiles+`; $d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$f=@{image_path='';image_path_redacted=$false};Set-PublicImagePath $d.value $f;[Console]::Out.Write(($f|ConvertTo-Json -Compress))`, data)
	var service ServiceFact
	if json.Unmarshal([]byte(result), &service) != nil || service.ImagePath != `C:\Program Files\OpenSSH\sshd.exe` || !service.ImagePathRedacted {
		t.Fatal("unrecognized service arguments escaped public-path filter")
	}
}

func TestOfflineEligibility(t *testing.T) {
	userExists := false
	good := Inspection{SystemSetupInProgress: 1, OOBEInProgress: 1, ImageStateKind: "generalized_to_oobe", UnattendPointerKind: "absent", AnswerDirectoryEmpty: true, GuestUserExists: &userExists, RunnerState: "unconfigured"}
	if !good.Eligible() {
		t.Fatal("clean generalized image rejected")
	}
	for _, mutate := range []func(*Inspection){func(i *Inspection) { i.GuestStatePresent = true }, func(i *Inspection) { i.RunnerState = "configured" }, func(i *Inspection) { i.RunnerState = "residue" }, func(i *Inspection) { i.RunnerState = "incomplete" }, func(i *Inspection) { i.RunnerState = "invalid" }, func(i *Inspection) { i.RunnerState = "unknown" }, func(i *Inspection) { i.FailureStep = 70 }} {
		bad := good
		mutate(&bad)
		if bad.Eligible() {
			t.Fatal("unsafe/unknown facts accepted")
		}
	}
	good.SAMHiveError = 5
	good.GuestUserExists = nil
	if !good.Eligible() {
		t.Fatal("informational SAM failure blocked eligibility")
	}
}

func TestWorkspaceLock(t *testing.T) {
	dir := t.TempDir()
	first, err := lockWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	if second, e := lockWorkspace(dir); e == nil {
		_ = second.Close()
		t.Fatal("concurrent cleanup acquired build lock")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := lockWorkspace(dir)
	if err != nil {
		t.Fatal("exited build lock not released")
	}
	defer func() { _ = second.Close() }()
	if err = os.Remove(filepath.Join(dir, "build.lock")); err != nil {
		t.Fatal("holder cannot unlink lock for final cleanup")
	}
	if err = os.RemoveAll(dir); err != nil {
		t.Fatal("holder cannot remove empty workspace while retaining lock")
	}
}

func TestSpaceAdmissionAndFinalPaths(t *testing.T) {
	required, err := requiredSpace(100, 0, false)
	if err != nil || required != (10<<30)+220 {
		t.Fatal("copy space formula")
	}
	required, err = requiredSpace(100, 200, true)
	if err != nil || required != (5<<30)+300 {
		t.Fatal("publication space formula")
	}
	if _, err = requiredSpace(0, 0, false); err == nil {
		t.Fatal("unknown size accepted")
	}
	check := SpaceCheck{Available: 1, Required: 2, Source: 3, Child: 4}
	if err = check.check(); err == nil || !strings.Contains(err.Error(), "available=1 required=2 source=3 child=4") {
		t.Fatal("space error lacks public byte counts")
	}
	for _, root := range []string{`D:\Templates\base`, `D:\Templates\base\Images`, `d:\templates`} {
		if disjointFinal(`D:\Templates\base\disk.vhdx`, root) == nil {
			t.Fatal("overlapping final paths accepted")
		}
	}
	if disjointFinal(`D:\Templates\base\disk.vhdx`, `D:\Images`) != nil {
		t.Fatal("separate final paths rejected")
	}
	f, err := os.CreateTemp(t.TempDir(), "source-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	// TEMP can be an 8.3 alias (CI runners use one); the final path is long.
	short, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	long := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(short, &long[0], windows.MAX_LONG_PATH)
	if err != nil || n == 0 || n >= windows.MAX_LONG_PATH {
		t.Fatal("long temp path unavailable")
	}
	actual, err := finalPath(windows.Handle(f.Fd()))
	if err != nil || !strings.EqualFold(actual, windows.UTF16ToString(long[:n])) {
		t.Fatal("final handle path mismatch")
	}
	if _, err = missingOwner("expected-template"); err == nil {
		t.Fatal("missing expected template accepted")
	}
	if _, err = missingOwner(""); err != nil {
		t.Fatal("optional owner record required")
	}
}

func TestAgentZeroCopies(t *testing.T) {
	host, guest := net.Pipe()
	defer func() { _ = host.Close(); _ = guest.Close() }()
	done := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(guest, "hello\n"); err != nil {
			done <- err
			return
		}
		r := bufio.NewReader(guest)
		for range 3 {
			if _, err := r.ReadString('\n'); err != nil {
				done <- err
				return
			}
		}
		if _, err := io.WriteString(guest, "gpu_copy_done:0\nidd_status:ok\nssh_ready\n"); err != nil {
			done <- err
			return
		}
		key, err := r.ReadString('\n')
		if err != nil {
			done <- err
			return
		}
		if key != "ssh_deploy_key public-key\n" {
			done <- errors.New("unexpected public-key frame")
			return
		}
		_, err = io.WriteString(guest, "ssh_key_deployed\n")
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := initializeDrivers(ctx, host, testConfig().Drivers, []byte("public-key")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
