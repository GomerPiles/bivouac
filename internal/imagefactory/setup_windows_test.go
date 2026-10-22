//go:build windows

package imagefactory

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "Windows", "Panther", "Unattend")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(dir, "setup-step.json")
}

// Extract only the status writer and redirect its fixed guest path into the
// fixture. Guest setup/specialize scripts are never executed as host scripts.
func fixtureStepWriter(t *testing.T, source string) string {
	t.Helper()
	start := strings.Index(source, "function Write-SetupStep")
	if start < 0 {
		t.Fatal("status writer missing")
	}
	end := strings.Index(source[start:], "\n}\n")
	if end < 0 {
		t.Fatal("status writer end missing")
	}
	return strings.ReplaceAll(source[start:start+end+3], `'C:\Windows\Panther\Unattend\setup-step.json'`, "$fixturePath")
}

func TestSetupStepNumericFacts(t *testing.T) {
	for _, test := range []struct {
		name, status string
		valid, video bool
	}{
		{"legacy", `{"step":70,"failed":true}`, true, false},
		{"specialize", `{"step":84,"failed":true}`, true, false},
		{"video", `{"step":35,"failed":true,"video":{"problem_code":14,"devnode_status":256,"ignored":"guest-private-output"}}`, true, true},
		{"zero", `{"step":35,"failed":true,"video":{"problem_code":0,"devnode_status":0}}`, true, true},
		{"max flags", `{"step":35,"failed":true,"video":{"problem_code":0,"devnode_status":4294967295}}`, true, true},
		{"text", `{"step":35,"failed":true,"video":{"problem_code":"14","devnode_status":256}}`, false, false},
		{"negative", `{"step":35,"failed":true,"video":{"problem_code":-1,"devnode_status":256}}`, false, false},
		{"fraction", `{"step":35,"failed":true,"video":{"problem_code":1.5,"devnode_status":256}}`, false, false},
		{"overflow", `{"step":35,"failed":true,"video":{"problem_code":0,"devnode_status":4294967296}}`, false, false},
		{"missing", `{"step":35,"failed":true,"video":{"problem_code":14}}`, false, false},
		{"wrong step", `{"step":36,"failed":true,"video":{"problem_code":14,"devnode_status":256}}`, false, false},
		{"not failed", `{"step":35,"failed":false,"video":{"problem_code":14,"devnode_status":256}}`, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, path := setupFixture(t)
			if err := os.WriteFile(path, []byte(test.status), 0600); err != nil {
				t.Fatal(err)
			}
			input, _ := json.Marshal(map[string]string{"root": root})
			script := offlineFiles + `
$data=[Console]::In.ReadToEnd()|ConvertFrom-Json;$facts=@{};$valid=$true
try{Read-SetupStep $data.root $facts}catch{$valid=$false}
[Console]::Out.Write((@{valid=$valid;facts=$facts}|ConvertTo-Json -Compress -Depth 4))`
			out := runTestPS(t, script, input)
			var report struct {
				Valid bool
				Facts Inspection
			}
			if json.Unmarshal([]byte(out), &report) != nil || report.Valid != test.valid || strings.Contains(out, "guest-private-output") {
				t.Fatal("numeric fact validation")
			}
			if test.valid && ((report.Facts.GuestSetupVideo != nil) != test.video) {
				t.Fatal("video diagnostics presence")
			}
			if test.valid {
				r := &record{}
				err := r.setupFailure(&report.Facts)
				if err == nil || !r.GuestSetupFailed || r.GuestSetupStep != report.Facts.GuestSetupStep || r.GuestSetupVideo != report.Facts.GuestSetupVideo {
					t.Fatal("record lost setup facts")
				}
				if test.video {
					b, _ := json.Marshal(r)
					pair := fmt.Sprintf("video problem_code=%d devnode_status=%d", report.Facts.GuestSetupVideo.ProblemCode, report.Facts.GuestSetupVideo.DevNodeStatus)
					if !strings.Contains(string(b), `"guest_setup_video"`) || !strings.Contains(err.Error(), pair) {
						t.Fatal("record/error lost video numbers")
					}
				}
			}
		})
	}
	if err := (&record{}).setupFailure(&Inspection{GuestSetupStep: 100}); err != nil {
		t.Fatal("success became failure")
	}
}

func TestSyntheticVerificationSteps(t *testing.T) {
	start := strings.Index(guestSetup, "if($display -eq 'synthetic'){\n function Get-VDDNodes")
	end := strings.Index(guestSetup, "$step=40;Write-SetupStep")
	if start < 0 || end <= start {
		t.Fatal("verification block missing")
	}
	// Only the read-only verification block is exercised, with all device reads
	// replaced by fixtures and one polling iteration instead of the 30 s wait.
	verify := strings.ReplaceAll(guestSetup[start:end], "$budget.Elapsed.TotalSeconds -lt 30", "$budget.Elapsed.TotalSeconds -lt 0")
	for _, test := range []struct {
		name                                     string
		problem, flags, step                     uint32
		nodes, packages, drivers, absent, failed bool
	}{
		{"ready", 0, 8, 38, false, false, false, false, false},
		{"needs restart", 14, 256, 35, false, false, false, false, true},
		{"not started", 0, 0, 35, false, false, false, false, true},
		{"absent", 0, 0, 35, false, false, false, true, true},
		{"nodes", 0, 8, 36, true, false, false, false, true},
		{"packages", 0, 8, 37, false, true, false, false, true},
		{"directory", 0, 8, 38, false, false, true, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, path := setupFixture(t)
			input, _ := json.Marshal(map[string]any{"root": root, "path": path, "problem": test.problem, "flags": test.flags, "nodes": test.nodes, "packages": test.packages, "drivers": test.drivers, "absent": test.absent})
			harness := `
$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json
$fixturePath=$data.path;$display='synthetic';$drivers='fixture-drivers';$videoDiagnostics=$null
function Get-PnpDevice {param($Class,[switch]$PresentOnly)
 if($Class -eq 'Display'){if(!$data.absent){[pscustomobject]@{InstanceId='fixture-video'}}}
 elseif($data.nodes){[pscustomobject]@{InstanceId='ROOT\APPSANDBOXVDD\fixture'}}
}
function Get-PnpDeviceProperty {param($InstanceId,$KeyName)
 $value=switch($KeyName){'DEVPKEY_Device_HardwareIds' {'VMBUS\{DA0A7802-0000-0000-0000-000000000000}'};'DEVPKEY_Device_ProblemCode' {$data.problem};'DEVPKEY_Device_DevNodeStatus' {$data.flags};default {throw 'fixture property'}}
 [pscustomobject]@{Data=$value}
}
function Get-WindowsDriver {param([switch]$Online,[switch]$All) if($data.packages){[pscustomobject]@{OriginalFileName='D:\Fixture\AppSandboxVDD.inf'}}}
function Test-Path {param($LiteralPath) if($LiteralPath -ne 'fixture-drivers'){throw 'unexpected path'};return $data.drivers}
function Start-Sleep {param($Milliseconds)}
`
			script := harness + fixtureStepWriter(t, guestSetup) + "\ntry {\n" + verify + "\n}catch{Write-SetupStep $step $true}\n" + `[Console]::Out.Write([IO.File]::ReadAllText($fixturePath))`
			out := runTestPS(t, script, input)
			var status struct {
				Step   uint32
				Failed bool
				Video  *SetupVideoStatus
			}
			if json.Unmarshal([]byte(out), &status) != nil || status.Step != test.step || status.Failed != test.failed {
				t.Fatal("verification condition did not identify its step")
			}
			expectVideo := test.step == 35 && !test.absent
			if (status.Video != nil) != expectVideo || (expectVideo && (status.Video.ProblemCode != test.problem || status.Video.DevNodeStatus != test.flags)) {
				t.Fatal("video pair missing or mismatched")
			}
		})
	}
}

func TestSyntheticSpecializeBarrier(t *testing.T) {
	start := strings.Index(guestSetup, " if($display -eq 'synthetic'){")
	end := strings.Index(guestSetup, " $step=10\n Write-SetupStep")
	if start < 0 || end <= start {
		t.Fatal("specialize guard missing")
	}
	guard := guestSetup[start:end]
	for _, test := range []struct {
		name, status, display string
		step                  uint32
		failed                bool
	}{
		{"completed", `{"step":88,"failed":false}`, "synthetic", 10, false},
		{"failed", `{"step":82,"failed":true}`, "synthetic", 82, true},
		{"interrupted", `{"step":84,"failed":false}`, "synthetic", 84, true},
		{"missing", "", "synthetic", 89, true},
		{"invalid", `{"step":"guest-private-output","failed":false}`, "synthetic", 89, true},
		{"vdd bypass", "", "vdd", 10, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, path := setupFixture(t)
			if test.status != "" {
				if err := os.WriteFile(path, []byte(test.status), 0600); err != nil {
					t.Fatal(err)
				}
			}
			input, _ := json.Marshal(map[string]string{"path": path, "display": test.display})
			script := `$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json;$fixturePath=$data.path;$display=$data.display;$step=10;$videoDiagnostics=$null
function Join-Path {param($Path,$ChildPath) return $fixturePath}
` + fixtureStepWriter(t, guestSetup) + "\ntry {\n" + guard + "\n$step=10;Write-SetupStep $step $false\n}catch{Write-SetupStep $step $true}\n" + `[Console]::Out.Write([IO.File]::ReadAllText($fixturePath))`
			var status struct {
				Step   uint32
				Failed bool
			}
			out := runTestPS(t, script, input)
			if json.Unmarshal([]byte(out), &status) != nil || status.Step != test.step || status.Failed != test.failed || strings.Contains(out, "guest-private-output") {
				t.Fatal("specialize failure was overwritten or bypassed")
			}
		})
	}
}

func TestSpecializeFailureStep(t *testing.T) {
	_, path := setupFixture(t)
	start := strings.Index(guestSpecialize, "function Write-SetupStep")
	end := strings.Index(guestSpecialize[start:], "\n}\n") + start + 3
	script := "$display='synthetic'\n$data=[Console]::In.ReadToEnd()|ConvertFrom-Json;$fixturePath=$data.path\nfunction Get-Service {throw 'fixture failure'}\n" + guestSpecialize[:start] + fixtureStepWriter(t, guestSpecialize) + guestSpecialize[end:]
	file := filepath.Join(t.TempDir(), "fixture-specialize.ps1")
	if err := os.WriteFile(file, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]string{"path": path})
	_, err := executeHost(t.Context(), file, input, false)
	var scriptErr *HostScriptError
	if !errors.As(err, &scriptErr) || scriptErr.Step != 80 {
		t.Fatal("specialize failure exit step")
	}
	b, err := os.ReadFile(path)
	var status struct {
		Step   uint32
		Failed bool
	}
	if err != nil || json.Unmarshal(b, &status) != nil || status.Step != 80 || !status.Failed {
		t.Fatal("specialize failure marker")
	}
}
