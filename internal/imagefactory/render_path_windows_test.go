//go:build windows

package imagefactory

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const pinnedProbeDirectory = `C:\ProgramData\BivouacHcsSpike`

func renderPathFixture(t *testing.T) string {
	t.Helper()
	start := strings.Index(guestValidate, " # Render-probe wait and failure diagnostics.")
	if start < 0 || !strings.Contains(guestValidate[start:], " $step=32\n") || strings.Count(guestValidate[start:], "[Diagnostics.Stopwatch]::StartNew()") != 1 {
		t.Fatal("render step missing")
	}
	// Include the helpers, budget selection, path bridge, nested cleanup and
	// final diagnostic catch together. Only the output path and clock are fake.
	step := guestValidate[start:]
	step = strings.ReplaceAll(step, "'"+pinnedProbeDirectory+"'", "$data.spike")
	step = strings.Replace(step, "[Diagnostics.Stopwatch]::StartNew()", "[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=$data.elapsed}}", 1)
	return "try{\n" + step
}

func TestPinnedRenderProbeOutputBridge(t *testing.T) {
	for _, mode := range []string{"success", "existing", "task exists", "register error", "start error", "ACL error", "timeout", "oversize", "directory", "junction", "hardlink", "destination exists", "malformed", "cleanup failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			base, spike, outside := filepath.Join(root, "probe"), filepath.Join(root, "spike"), filepath.Join(root, "outside")
			for _, directory := range []string{base, outside} {
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(outside, "public.txt"), []byte("public fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "existing" {
				if err := os.Mkdir(spike, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "destination exists" {
				if err := os.WriteFile(filepath.Join(base, "render.json"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			report := `{"desktop_ready":true,"hardware_d3d11":true,"presented":true,"pixel_readback":true,"stage":7,"hresult":0}`
			elapsed := 0
			if mode == "timeout" || mode == "cleanup failure" {
				elapsed = 50
			}
			data, _ := json.Marshal(map[string]any{"mode": mode, "base": base, "spike": spike, "outside": outside, "report": report, "root": root, "elapsed": elapsed, "require_setup": false})
			script := `$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json
$base=$data.base;$probe=Join-Path $base 'render.exe';$rotated=$false;$session=2
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
$topology=@{topology_valid=$true;virtual_equals_primary=$true;hyperv_video_enabled=$true;hyperv_video_started=$true;probe_foreground=$true;probe_on_primary=$true;probe_input_received=$true;security_window_found=$false;security_on_primary=$false}
$gpuStatus=@{valid=$true;display_count=1;virtual_count=1;problem_code=0}
function Set-Acl {param($LiteralPath,$AclObject)
 if($LiteralPath -ne $data.spike -or $AclObject.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'){throw 'wrong ACL'}
 if($data.mode -eq 'ACL error'){throw 'fixture ACL failure'}
}
function Get-ScheduledTask {param($TaskName,$ErrorAction) if($data.mode -eq 'task exists'){return $true};if($renderRegistered){[IO.File]::WriteAllText((Join-Path $data.root 'diagnostic-before-cleanup'),([int](Test-Path -LiteralPath $data.spike)).ToString());return [pscustomobject]@{State=4}}}
function Get-ScheduledTaskInfo {param($TaskName,$ErrorAction) [pscustomobject]@{LastTaskResult=0x41301}}
function Get-Process {param($ErrorAction)}
function Get-CimInstance {param($ClassName,$Filter,$OperationTimeoutSec,$ErrorAction)}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel)}
function New-ScheduledTaskAction {param($Execute,$WorkingDirectory)}
function New-ScheduledTaskSettingsSet {param($ExecutionTimeLimit,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries)}
function Register-ScheduledTask {param($TaskName,$Principal,$Action,$Settings) if($data.mode -eq 'register error'){throw 'fixture registration failure'}}
function Start-ScheduledTask {param($TaskName)
 if($data.mode -eq 'start error'){throw 'fixture start failure'}
 if($data.mode -in @('timeout','cleanup failure')){return}
 $path=Join-Path $data.spike 'render.json'
 switch($data.mode){
  'oversize' {[IO.File]::WriteAllText($path,('x'*4097))}
  'directory' {[void][IO.Directory]::CreateDirectory($path)}
  'junction' {New-Item -ItemType Junction -Path $path -Target $data.outside | Out-Null}
  'hardlink' {New-Item -ItemType HardLink -Path $path -Target (Join-Path $data.outside 'public.txt') | Out-Null}
  'malformed' {[IO.File]::WriteAllText($path,'invalid')}
  default {[IO.File]::WriteAllText($path,$data.report)}
 }
}
function Stop-ScheduledTask {param($TaskName,$ErrorAction) [IO.File]::WriteAllText((Join-Path $data.root 'stopped'),'true');if($data.mode -eq 'cleanup failure'){[IO.File]::WriteAllText((Join-Path $data.spike 'unexpected'),'preserve')}}
function Unregister-ScheduledTask {param($TaskName,[switch]$Confirm) [IO.File]::WriteAllText((Join-Path $data.root 'unregistered'),'true')}
` + renderPathFixture(t)
			system, err := windows.GetSystemDirectory()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "fixture.ps1")
			if err := os.WriteFile(path, []byte(script), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
			cmd.Env = hostPowerShellEnvironment(system)
			cmd.Stdin = strings.NewReader(string(data))
			output, err := cmd.Output()
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal("fixture could not run")
				}
				code = exit.ExitCode()
			}
			want := 33
			switch mode {
			case "success":
				want = 0
			case "existing", "ACL error":
				want = 32
			case "task exists":
				want = 15
			case "register error":
				want = 23
			case "start error":
				want = 24
			case "timeout":
				want = 16
			case "malformed":
				want = 25
			case "cleanup failure":
				want = 34
			}
			if code != want {
				t.Fatalf("render step exit %d, want %d", code, want)
			}
			registered := mode != "existing" && mode != "ACL error" && mode != "task exists" && mode != "register error"
			for _, marker := range []string{"stopped", "unregistered"} {
				_, err := os.Stat(filepath.Join(root, marker))
				if (err == nil) != registered {
					t.Fatal("render task cleanup did not follow registration")
				}
			}
			_, statErr := os.Lstat(spike)
			if mode == "existing" || mode == "cleanup failure" {
				if statErr != nil {
					t.Fatal("pre-existing or unconfirmed output directory removed")
				}
			} else if !os.IsNotExist(statErr) {
				t.Fatal("owned spike directory remains")
			}
			if mode == "success" {
				b, err := os.ReadFile(filepath.Join(base, "render.json"))
				if err != nil || string(b) != report || !json.Valid(output) {
					t.Fatal("report was not relocated and decoded")
				}
			}
			if mode == "timeout" || mode == "cleanup failure" {
				if probeFailureShape(output) == "" {
					t.Fatal("timeout lost numeric diagnostics")
				}
				if b, err := os.ReadFile(filepath.Join(root, "diagnostic-before-cleanup")); err != nil || string(b) != "1" {
					t.Fatal("timeout diagnostics ran after spike cleanup")
				}
			}
			if mode == "cleanup failure" {
				if b, err := os.ReadFile(filepath.Join(spike, "unexpected")); err != nil || string(b) != "preserve" {
					t.Fatal("cleanup deleted an unexpected entry")
				}
			}
			if b, err := os.ReadFile(filepath.Join(outside, "public.txt")); err != nil || string(b) != "public fixture" {
				t.Fatal("cleanup followed a link")
			}
			if mode == "destination exists" {
				if b, err := os.ReadFile(filepath.Join(base, "render.json")); err != nil || string(b) != "preserve" {
					t.Fatal("existing report overwritten")
				}
			}
		})
	}
}

func TestPinnedProbeGeneratedContractAndSanitation(t *testing.T) {
	if strings.Count(guestValidate, pinnedProbeDirectory) != 1 {
		t.Fatal("pinned output path must be named once")
	}
	for _, token := range []string{"New-Item -ItemType Directory -Path $spikeBase", "Set-Acl -LiteralPath $spikeBase -AclObject $acl", "$result=Join-Path $spikeBase 'render.json'", "$output.LinkType", "$output.Length -gt 4096", "Move-Item -LiteralPath $result -Destination $destination", "[IO.Directory]::Delete($spikeBase,$false)", "if($spikeOwned)"} {
		if !strings.Contains(guestValidate, token) {
			t.Fatal("generated render bridge missing", token)
		}
	}
	guard := "if(Test-Path -LiteralPath '" + pinnedProbeDirectory + "'){exit 32}"
	if !strings.Contains(imageSanitize, guard) {
		t.Fatal("sanitation guard missing")
	}
	for _, present := range []bool{false, true} {
		input, _ := json.Marshal(present)
		script := "$exists=[Console]::In.ReadToEnd()|ConvertFrom-Json;function Test-Path {param($LiteralPath) return $exists};" + strings.ReplaceAll(guard, "exit 32", "[Console]::Out.Write('32');exit 0") + ";[Console]::Out.Write('0')"
		want := "0"
		if present {
			want = "32"
		}
		if runTestPS(t, script, input) != want {
			t.Fatal("sanitation accepted a leftover spike directory")
		}
	}
}
