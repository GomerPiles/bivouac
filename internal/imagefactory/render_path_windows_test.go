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

// Include the real diagnostic helper but replace every native security query.
// Explicit decrypted/off values distinguish successful CIM reads from the helper's
// unavailable-value fallback; none of these fixtures reads host security state.
func renderSecurityFixture(t *testing.T) string {
	t.Helper()
	start := strings.Index(guestValidate, "function Read-BitLockerDiagnostics")
	if start < 0 {
		t.Fatal("BitLocker helper missing")
	}
	end := strings.Index(guestValidate[start:], "\n}\n")
	if end < 0 {
		t.Fatal("BitLocker helper boundary missing")
	}
	return guestValidate[start:start+end+3] + `
function Confirm-SecureBootUEFI {return $true}
function Get-Tpm {return [pscustomobject]@{TpmPresent=$true;TpmReady=$true}}
function Invoke-CimMethod {param($InputObject,$MethodName,$OperationTimeoutSec)
 if($InputObject.Fixed -ne 1 -or $OperationTimeoutSec -ne 10){throw 'CIM scope'}
 switch -CaseSensitive ($MethodName){
  'GetConversionStatus' {return [pscustomobject]@{ReturnValue=0;ConversionStatus=0}}
  'GetProtectionStatus' {return [pscustomobject]@{ReturnValue=0;ProtectionStatus=0}}
  default {throw 'CIM method'}
 }
}
`
}

func assertRenderSecurityReport(t *testing.T, output []byte) {
	t.Helper()
	var report map[string]json.RawMessage
	if json.Unmarshal(output, &report) != nil {
		t.Fatal("merged render report is not JSON")
	}
	for field, want := range map[string]string{
		"secure_boot": "true", "tpm_present": "true", "tpm_ready": "true",
		"bitlocker_conversion_status": "0", "bitlocker_protection_status": "0",
		"guest_ready": "true", "credential_rotated": "false",
		"desktop_ready": "true", "hardware_d3d11": "true", "presented": "true", "pixel_readback": "true",
		"stage": "7", "hresult": "0", "gpu_device_diagnostics_valid": "true",
		"topology_valid": "true", "virtual_equals_primary": "true", "hyperv_video_enabled": "true", "hyperv_video_started": "true",
		"probe_foreground": "true", "probe_on_primary": "true", "probe_input_received": "true",
		"security_window_found": "false", "security_on_primary": "false",
	} {
		if string(report[field]) != want {
			t.Fatal("merged render report field changed:", field)
		}
	}
	security, err := parseGuestSecurity(output)
	if err != nil || security != (GuestSecurity{SecureBoot: true, TPMPresent: true, TPMReady: true, BitLockerConversionStatus: 0, BitLockerProtectionStatus: 0}) {
		t.Fatal("merged render security report was not preserved by the consumer")
	}
}

func renderPathFixture(t *testing.T) string {
	t.Helper()
	start := strings.Index(guestValidate, " # Render-probe wait and failure diagnostics.")
	if start < 0 || !strings.Contains(guestValidate[start:], " $step=32\n") || strings.Count(guestValidate[start:], "[Diagnostics.Stopwatch]::StartNew()") != 1 {
		t.Fatal("render step missing")
	}
	// Include the helpers, budget selection, path bridge, nested cleanup and
	// final diagnostic catch together. Relocate the output path and fake the
	// clock; the caller and security fixture stub native observations/actions.
	step := guestValidate[start:]
	step = strings.ReplaceAll(step, "'"+pinnedProbeDirectory+"'", "$data.spike")
	step = strings.Replace(step, "[RenderOutputDirectory]::Create($spikeBase,$security)", "(New-TestProbeDirectory $spikeBase $acl)", 1)
	step = strings.Replace(step, "[Diagnostics.Stopwatch]::StartNew()", "[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=$data.elapsed}}", 1)
	return renderSecurityFixture(t) + "try{\n" + step
}

func TestPinnedRenderProbeOutputBridge(t *testing.T) {
	for _, mode := range []string{"success", "existing", "task exists", "register error", "start error", "ACL error", "timeout", "oversize", "directory", "junction", "hardlink", "destination exists", "malformed", "cleanup failure", "task cleanup failure", "start cleanup failure", "creation race", "wrong owner", "wrong DACL", "unprotected DACL", "nonempty creation"} {
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
function New-TestProbeDirectory {param($LiteralPath,$AclObject)
 if($LiteralPath -ne $data.spike -or $AclObject.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'){throw 'wrong ACL'}
 if($AclObject.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544'){throw 'wrong owner requested'}
 if($data.mode -eq 'ACL error'){throw 'fixture ACL failure'}
 [void][IO.Directory]::CreateDirectory($LiteralPath)
 if($data.mode -eq 'creation race'){[IO.File]::WriteAllText((Join-Path $LiteralPath 'foreign.txt'),'preserve');return 183}
 if($data.mode -eq 'nonempty creation'){[IO.File]::WriteAllText((Join-Path $LiteralPath 'foreign.txt'),'preserve')}
 return 0
}
function Get-Acl {param($LiteralPath)
 if($LiteralPath -ne $data.spike){throw 'foreign ACL query'}
 $copy=[Security.AccessControl.DirectorySecurity]::new();$copy.SetSecurityDescriptorSddlForm($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All))
 if($data.mode -eq 'wrong owner'){$copy.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))}
 if($data.mode -eq 'wrong DACL'){$copy.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;BA)')}
 if($data.mode -eq 'unprotected DACL'){$copy.SetAccessRuleProtection($false,$true)}
 return $copy
}
function Get-ScheduledTask {param($TaskName,$ErrorAction) if($data.mode -eq 'task exists'){return $true};if($renderRegistered){[IO.File]::WriteAllText((Join-Path $data.root 'diagnostic-before-cleanup'),([int](Test-Path -LiteralPath $data.spike)).ToString());return [pscustomobject]@{State=4}}}
function Get-ScheduledTaskInfo {param($TaskName,$ErrorAction) [pscustomobject]@{LastTaskResult=0x41301}}
function Get-Process {param($ErrorAction)}
function Get-CimInstance {param($Namespace,$ClassName,$Filter,$OperationTimeoutSec,$ErrorAction)
 if($Namespace -ceq 'root\CIMV2\Security\MicrosoftVolumeEncryption' -and $ClassName -ceq 'Win32_EncryptableVolume' -and $Filter -ceq "DriveLetter='C:'" -and $OperationTimeoutSec -eq 10){return [pscustomobject]@{Fixed=1}}
 if($ClassName -cne 'Win32_PnPEntity' -or $Namespace){throw 'CIM scope'}
}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel)}
function New-ScheduledTaskAction {param($Execute,$WorkingDirectory)}
function New-ScheduledTaskSettingsSet {param($ExecutionTimeLimit,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries)}
function Register-ScheduledTask {param($TaskName,$Principal,$Action,$Settings) if($data.mode -eq 'register error'){throw 'fixture registration failure'}}
function Start-ScheduledTask {param($TaskName)
 if($data.mode -in @('start error','start cleanup failure')){throw 'fixture start failure'}
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
function Stop-ScheduledTask {param($TaskName,$ErrorAction) [IO.File]::WriteAllText((Join-Path $data.root 'stopped'),'true');if($data.mode -eq 'cleanup failure'){[IO.File]::WriteAllText((Join-Path $data.spike 'unexpected'),'preserve')};if($data.mode -in @('task cleanup failure','start cleanup failure')){throw 'fixture cleanup failure'}}
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
			case "existing", "ACL error", "creation race", "wrong owner", "wrong DACL", "unprotected DACL", "nonempty creation":
				want = 32
			case "task exists":
				want = 15
			case "register error":
				want = 23
			case "start error", "start cleanup failure":
				want = 24
			case "timeout", "cleanup failure":
				want = 16
			case "malformed":
				want = 25
			case "task cleanup failure":
				want = 34
			}
			if code != want {
				t.Fatalf("render step exit %d, want %d", code, want)
			}
			registered := mode != "existing" && mode != "ACL error" && mode != "task exists" && mode != "register error" && mode != "creation race" && mode != "wrong owner" && mode != "wrong DACL" && mode != "unprotected DACL" && mode != "nonempty creation"
			for _, marker := range []string{"stopped", "unregistered"} {
				_, err := os.Stat(filepath.Join(root, marker))
				if (err == nil) != registered {
					t.Fatal("render task cleanup did not follow registration")
				}
			}
			_, statErr := os.Lstat(spike)
			if mode == "existing" || mode == "cleanup failure" || mode == "creation race" || mode == "nonempty creation" {
				if statErr != nil {
					t.Fatal("pre-existing or unconfirmed output directory removed")
				}
			} else if !os.IsNotExist(statErr) {
				t.Fatal("owned spike directory remains")
			}
			if mode == "creation race" || mode == "nonempty creation" {
				if b, err := os.ReadFile(filepath.Join(spike, "foreign.txt")); err != nil || string(b) != "preserve" {
					t.Fatal("foreign entry changed")
				}
			}
			if mode == "success" {
				b, err := os.ReadFile(filepath.Join(base, "render.json"))
				if err != nil || string(b) != report || !json.Valid(output) {
					t.Fatal("report was not relocated and decoded")
				}
				assertRenderSecurityReport(t, output)
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
	for _, token := range []string{"[RenderOutputDirectory]::Create($spikeBase,$security)", "$result=Join-Path $spikeBase 'render.json'", "$output.LinkType", "$output.Length -gt 4096", "Move-Item -LiteralPath $result -Destination $destination", "[IO.Directory]::Delete($spikeBase,$false)", "if($spikeOwned)"} {
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

func renderDirectoryFixture(t *testing.T) string {
	t.Helper()
	start := strings.Index(guestValidate, " function Initialize-RenderDirectory")
	end := strings.Index(guestValidate, " function Write-RenderProbeFailure")
	if start < 0 || end <= start {
		t.Fatal("render directory helpers missing")
	}
	return guestValidate[start:end]
}

func TestRenderProbeAtomicDirectoryACL(t *testing.T) {
	input, _ := json.Marshal(map[string]string{"path": filepath.Join(t.TempDir(), "probe")})
	// Exercise the real native helper with this unelevated fixture principal as
	// owner, never the fixed guest path or an administrator-only host directory.
	script := renderDirectoryFixture(t) + `$ErrorActionPreference='Stop';$d=[Console]::In.ReadToEnd()|ConvertFrom-Json
Initialize-RenderDirectory
$acl=[Security.AccessControl.DirectorySecurity]::new()
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$acl.SetSecurityDescriptorSddlForm(('O:'+$sid+'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;'+$sid+')'))
$security=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access)
$code=[RenderOutputDirectory]::Create($d.path,$security);if($code -ne 0){throw ('create code={0}' -f $code)}
Assert-RenderDirectory $d.path $acl
$foreign=Join-Path $d.path 'foreign.txt';[IO.File]::WriteAllText($foreign,'preserve')
$before=(Get-Acl -LiteralPath $d.path).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
$other=[Security.AccessControl.DirectorySecurity]::new();$other.SetSecurityDescriptorSddlForm(('O:'+$sid+'D:P(A;OICI;FA;;;'+$sid+')'))
$code=[RenderOutputDirectory]::Create($d.path,$other.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All))
if($code -ne 183 -or (Get-Acl -LiteralPath $d.path).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All) -cne $before -or [IO.File]::ReadAllText($foreign) -cne 'preserve'){throw 'existing directory adopted or changed'}
[Console]::Out.Write('atomic')`
	if got := runTestPS(t, script, input); got != "atomic" {
		t.Fatal("native exclusive probe-directory creation failed")
	}
}
