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

	"github.com/GomerPiles/bivouac/internal/guestagent"
)

func testProbeFailure() probeFailureReport {
	return probeFailureReport{TaskObserved: true, TaskState: 4, LastResult: 0x41301, ProcessObserved: true, RenderCount: 1, RenderRunning: true, RenderCPUMS: 1500, DisplayObserved: true, PresentDisplays: 2, GPUCount: 1, GPUObserved: true, GPUDevnode: 8, ExplorerObserved: true, ExplorerAge: 120, WaitSeconds: 180, WaitBudget: 180}
}

func TestProbeFailureStrictSchema(t *testing.T) {
	b, _ := json.Marshal(testProbeFailure())
	if shape := probeFailureShape(b); !strings.Contains(shape, "last_result=0x00041301") || !strings.Contains(shape, "render_cpu_ms=1500") {
		t.Fatal("numeric diagnostic lost")
	}
	for _, malformed := range [][]byte{
		nil, []byte(`[]`), []byte(`null`), append(append([]byte{}, b...), b...),
		append([]byte(strings.Repeat(" ", probeFailureLimit)), b...),
		[]byte(strings.Replace(string(b), `"task_state":4`, `"task_state":"private-text"`, 1)),
		[]byte(strings.Replace(string(b), `"task_state":4`, `"task_state":null`, 1)),
		[]byte(strings.Replace(string(b), `"task_state":4`, `"task_state":4,"private-field":1`, 1)),
		[]byte(strings.Replace(string(b), `"task_state":4`, `"private-field":4`, 1)),
		[]byte(strings.Replace(string(b), `"task_state":4`, `"TASK_STATE":4`, 1)),
		[]byte(strings.Replace(string(b), `"task_state":4`, `"task_state":4,"task_state":4`, 1)),
		[]byte(strings.Replace(string(b), `"task_state":4,`, ``, 1)),
		[]byte(strings.Replace(string(b), `"task_state":4`, `"task_state":4.5`, 1)),
		[]byte(strings.Replace(string(b), `"last_result":267009`, `"last_result":4294967296`, 1)),
		[]byte(strings.Replace(string(b), `"render_running":true`, `"render_running":"private-text"`, 1)),
	} {
		if probeFailureShape(malformed) != "" {
			t.Fatal("non-schema diagnostic accepted")
		}
		fake := fakeFactoryAgent(func([]string, []byte) ([]byte, int) { return malformed, 16 })
		out, err := guestRun(t.Context(), fake, validateEntry, nil)
		if out != nil || err == nil || err.Error() != "fixed guest operation exited at step 16" {
			t.Fatal("malformed diagnostic disclosed or changed failure")
		}
	}
	fake := fakeFactoryAgent(func([]string, []byte) ([]byte, int) { return b, 16 })
	_, err := guestRun(t.Context(), fake, "inline runner check", nil)
	if err == nil || err.Error() != "fixed guest operation exited at step 16" {
		t.Fatal("diagnostic accepted outside validation")
	}
}

// Run the complete merged render step, with real temporary report relocation
// and fixed task/device observations. No real task, device or guest is used.
func TestRealRenderProbeFailures(t *testing.T) {
	dial := localAgent(t)
	const report = `{"desktop_ready":true,"hardware_d3d11":true,"presented":true,"pixel_readback":true,"stage":7,"hresult":0,"vendor_id":4098,"device_id":1,"adapter_count":2,"hardware_adapter_count":1}`
	mocks := `
$script:taskCalls=0;$session=2;$probe='fixture';$base=$data.base;$rotated=$false
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
$topology=@{topology_valid=$true;virtual_equals_primary=$true;hyperv_video_enabled=$true;hyperv_video_started=$true;probe_foreground=$true;probe_on_primary=$true;probe_input_received=$true;security_window_found=$false;security_on_primary=$false;active_display_count=1;primary_display_count=1;primary_width=1024;primary_height=768;primary_adapter_kind=1;vdd_node_count=0}
$gpuStatus=@{valid=$true;display_count=2;virtual_count=1;problem_code=0}
function Set-Acl {param($LiteralPath,$AclObject) if($LiteralPath -ne $data.spike -or $AclObject.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'){throw 'wrong ACL'}}
function Get-ScheduledTask {param($TaskName,$ErrorAction) $script:taskCalls++;if($script:taskCalls -eq 1){return};[IO.File]::WriteAllText((Join-Path $data.root 'diagnostic-before-cleanup'),([int](Test-Path -LiteralPath $data.spike)).ToString());if($data.observation_failure){throw 'fixture'};[pscustomobject]@{State=4}}
function Get-ScheduledTaskInfo {param($TaskName,$ErrorAction) [pscustomobject]@{LastTaskResult=$data.last_result}}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel) return 1}
function New-ScheduledTaskAction {param($Execute,$WorkingDirectory) return 1}
function New-ScheduledTaskSettingsSet {param($ExecutionTimeLimit,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries) $want=80;if($data.require_setup){$want=210};if($ExecutionTimeLimit.TotalSeconds -ne $want){throw 'task limit'};return 1}
function Register-ScheduledTask {param($TaskName,$Principal,$Action,$Settings)}
function Stop-ScheduledTask {param($TaskName,$ErrorAction) [IO.File]::WriteAllText((Join-Path $data.root 'stopped'),'true')}
function Unregister-ScheduledTask {param($TaskName,$Confirm) [IO.File]::WriteAllText((Join-Path $data.root 'unregistered'),'true')}
function Start-ScheduledTask {param($TaskName) if($data.start_failure){throw 'fixture'}}
function Start-Sleep {param($Milliseconds) $text=$data.report;if($data.bad_report){$text='private-text'};[IO.File]::WriteAllText((Join-Path $data.spike 'render.json'),$text)}
# Preserve the step-25 size guard by growing the initially valid report only
# after upstream's step-33 validation and move have succeeded.
function Move-Item {param($LiteralPath,$Destination) Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination;if($data.oversize){[IO.File]::WriteAllText($Destination,('x'*4097))}}
function Get-Date {return [datetime]'2026-01-01T00:02:00Z'}
function Get-Process {param($ErrorAction) if($data.observation_failure){throw 'fixture'};[pscustomobject]@{ProcessName='render';SessionId=2;TotalProcessorTime=[timespan]::FromMilliseconds(1500)};[pscustomobject]@{ProcessName='render';SessionId=3;TotalProcessorTime=[timespan]::FromMilliseconds(9000)};[pscustomobject]@{ProcessName='explorer';SessionId=2;StartTime=[datetime]'2026-01-01T00:00:00Z'}}
function Get-CimInstance {param($ClassName,$Filter,$OperationTimeoutSec,$ErrorAction) if($data.observation_failure){throw 'fixture'};[pscustomobject]@{Present=$true;DeviceID='PCI\VEN_1414&DEV_008E';ConfigManagerErrorCode=0};[pscustomobject]@{Present=$true;DeviceID='VMBUS\fixture';ConfigManagerErrorCode=0}}
function Get-PnpDeviceProperty {param($InstanceId,$KeyName,$ErrorAction) [pscustomobject]@{Data=[uint32]8}}
`
	script := `param($data);$ErrorActionPreference='Stop';if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){exit 19};` + mocks + renderPathFixture(t)
	for _, tc := range []struct {
		name    string
		setup   bool
		elapsed int
		code    int
		field   string
	}{
		{"factory-timeout", true, 180, 16, ""}, {"lab-timeout", false, 50, 16, ""},
		{"factory-within-budget", true, 100, 0, ""}, {"lab-over-budget", false, 100, 16, ""},
		{"start-failure", true, 0, 24, "start_failure"}, {"oversize-report", true, 0, 25, "oversize"},
		{"invalid-report", true, 0, 25, "bad_report"}, {"unavailable-observations", true, 180, 16, "observation_failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			base, spike := filepath.Join(root, "probe"), filepath.Join(root, "spike")
			if err := os.Mkdir(base, 0700); err != nil {
				t.Fatal(err)
			}
			data := map[string]any{"require_setup": tc.setup, "elapsed": tc.elapsed, "last_result": 0x41301, "root": root, "base": base, "spike": spike, "report": report}
			if tc.field != "" {
				data[tc.field] = true
			}
			out, err := runBootstrap(t, dial, guestBootstrap, script, data)
			if _, err := os.Lstat(spike); !os.IsNotExist(err) {
				t.Fatal("owned spike directory remains")
			}
			for _, marker := range []string{"stopped", "unregistered"} {
				if _, err := os.Stat(filepath.Join(root, marker)); err != nil {
					t.Fatal("render task cleanup missing")
				}
			}
			if tc.code == 0 {
				if err != nil || factoryDisplayReportOK(out) != nil {
					t.Fatal("factory budget did not allow a late report")
				}
				if b, err := os.ReadFile(filepath.Join(base, "render.json")); err != nil || string(b) != report {
					t.Fatal("late report was not relocated")
				}
				return
			}
			var exit *guestagent.ExitError
			if !errors.As(err, &exit) || exit.Code != tc.code {
				t.Fatalf("wrong failure step: want=%d", tc.code)
			}
			if tc.code == 16 {
				if b, err := os.ReadFile(filepath.Join(root, "diagnostic-before-cleanup")); err != nil || string(b) != "1" {
					t.Fatal("timeout diagnostics ran after spike cleanup")
				}
			}
			shape := probeFailureShape(out)
			var report probeFailureReport
			if shape == "" || json.Unmarshal(out, &report) != nil || report.WaitSeconds != uint32(tc.elapsed) {
				t.Fatal("real PowerShell diagnostic invalid")
			} // #nosec G115 -- small fixed fixture elapsed values.
			wantBudget := uint32(50)
			if tc.setup {
				wantBudget = 180
			}
			if report.WaitBudget != wantBudget {
				t.Fatal("wrong first-boot budget")
			}
			if tc.field == "observation_failure" {
				if report.TaskObserved || report.ProcessObserved || report.DisplayObserved || report.GPUObserved || report.ExplorerObserved {
					t.Fatal("unavailable facts marked observed")
				}
			} else if report.TaskState != 4 || report.LastResult != 0x41301 || report.RenderCount != 1 || report.RenderCPUMS != 1500 || report.PresentDisplays != 2 || report.GPUDevnode != 8 || report.ExplorerAge != 120 {
				t.Fatal("numeric facts changed")
			}
			fake := fakeFactoryAgentFrames(func([]string, []byte) ([]byte, int) { return out, tc.code }, 1, 3)
			got, err := guestRun(t.Context(), fake, validateEntry, nil)
			if got != nil || err == nil || err.Error() != fmt.Sprintf("fixed guest operation exited at step %d (%s)", tc.code, shape) {
				t.Fatal("real diagnostic lost in agent framing")
			}
			fake = fakeFactoryAgent(answerInstallation(func(_ []string, input []byte) ([]byte, int) {
				if len(input) == 0 {
					return nil, 0
				}
				return out, tc.code
			}))
			r := &record{}
			err = prepareGuestWithDial(t.Context(), testConfig(), r, fake)
			if err == nil || !strings.Contains(err.Error(), shape) || strings.Contains(err.Error(), "invalid topology report") || r.Manifest.Topology != nil {
				t.Fatal("failed report reached topology decode or manifest")
			}
			t.Logf("step=%d stdout_len=%d budget_seconds=%d", tc.code, len(out), report.WaitBudget)
		})
	}
}
