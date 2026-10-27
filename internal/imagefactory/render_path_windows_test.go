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
	start := strings.Index(guestValidate, " $step=32\n")
	end := strings.LastIndex(guestValidate, "\n exit 0")
	if start < 0 || end <= start {
		t.Fatal("render step missing")
	}
	step := guestValidate[start:end]
	step = strings.ReplaceAll(step, "'"+pinnedProbeDirectory+"'", "$data.spike")
	// Exercise the existing timeout exit without waiting or running a task.
	return strings.ReplaceAll(step, "$probeBudget.Elapsed.TotalSeconds -gt 50", "$probeBudget.Elapsed.TotalSeconds -gt -1")
}

func TestPinnedRenderProbeOutputBridge(t *testing.T) {
	for _, mode := range []string{"success", "existing", "task exists", "register error", "start error", "ACL error", "timeout", "oversize", "directory", "junction", "hardlink", "destination exists", "malformed"} {
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
			data, _ := json.Marshal(map[string]string{"mode": mode, "base": base, "spike": spike, "outside": outside, "report": report, "root": root})
			script := `$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json
$base=$data.base;$probe=Join-Path $base 'render.exe';$rotated=$false
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
$topology=@{topology_valid=$true;virtual_equals_primary=$true;hyperv_video_enabled=$true;hyperv_video_started=$true;probe_foreground=$true;probe_on_primary=$true;probe_input_received=$true;security_window_found=$false;security_on_primary=$false}
$gpuStatus=@{valid=$true;display_count=1;virtual_count=1;problem_code=0}
function Set-Acl {param($LiteralPath,$AclObject)
 if($LiteralPath -ne $data.spike -or $AclObject.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'){throw 'wrong ACL'}
 if($data.mode -eq 'ACL error'){throw 'fixture ACL failure'}
}
function Get-ScheduledTask {param($TaskName,$ErrorAction) if($data.mode -eq 'task exists'){return $true}}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel)}
function New-ScheduledTaskAction {param($Execute,$WorkingDirectory)}
function New-ScheduledTaskSettingsSet {param($ExecutionTimeLimit,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries)}
function Register-ScheduledTask {param($TaskName,$Principal,$Action,$Settings) if($data.mode -eq 'register error'){throw 'fixture registration failure'}}
function Start-ScheduledTask {param($TaskName)
 if($data.mode -eq 'start error'){throw 'fixture start failure'}
 if($data.mode -eq 'timeout'){return}
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
function Stop-ScheduledTask {param($TaskName,$ErrorAction) [IO.File]::WriteAllText((Join-Path $data.root 'stopped'),'true')}
function Unregister-ScheduledTask {param($TaskName,[switch]$Confirm) [IO.File]::WriteAllText((Join-Path $data.root 'unregistered'),'true')}
try{
` + renderPathFixture(t) + "\n}catch{exit $step}\n"
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
			if mode == "existing" {
				if statErr != nil {
					t.Fatal("pre-existing output directory removed")
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
