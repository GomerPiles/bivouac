//go:build windows

package imagefactory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/guestagent"
)

func TestRunnerTaskRegistrationXML(t *testing.T) {
	start, end := strings.Index(guestSetup, "# Fixed XML"), strings.Index(guestSetup, "$step=60;")
	if start < 0 || end <= start {
		t.Fatal("registration block unavailable")
	}
	guardStart, guardEnd := strings.Index(guestSetup, "# Check both tasks"), strings.Index(guestSetup, "$principal=New-ScheduledTaskPrincipal")
	if guardStart < 0 || guardEnd <= guardStart || guardEnd > strings.Index(guestSetup, "Register-ScheduledTask") {
		t.Fatal("task prechecks do not precede registration")
	}
	for _, existing := range []string{"", "bivouac-guest-agent", "bivouac-guest-runner"} {
		exists := existing != ""
		input, _ := json.Marshal(map[string]string{"existing": existing})
		script := `$ErrorActionPreference='Stop';$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$registered=$false;$refused=$false
function Get-ScheduledTask {param($TaskName,$ErrorAction) if($TaskName -cnotin @('bivouac-guest-agent','bivouac-guest-runner')){throw 'wrong task'};if($d.existing -ceq $TaskName){[pscustomobject]@{State=3}}}
function Register-ScheduledTask {param($TaskName,$Xml)
 if($TaskName -cne 'bivouac-guest-runner'){throw 'wrong task'}
 $x=[xml]$Xml;$t=$x.Task
 if($t.Triggers.ChildNodes.Count -ne 0 -or $t.Principals.Principal.Count -gt 1 -or $t.Principals.Principal.UserId -cne ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -or $t.Principals.Principal.LogonType -cne 'InteractiveToken' -or $t.Principals.Principal.RunLevel -cne 'HighestAvailable'){throw 'principal or trigger'}
 if($t.Actions.ChildNodes.Count -ne 1 -or $t.Actions.Exec.Command -cne 'C:\Program Files\Bivouac\bivouac.exe' -or $t.Actions.Exec.Arguments -cne 'guest windows detached' -or $t.Actions.Exec.WorkingDirectory -cne 'C:\ProgramData\Bivouac\Guest'){throw 'action'}
 if($t.Settings.Priority -cne '4' -or $t.Settings.ExecutionTimeLimit -cne 'PT0S' -or $t.Settings.MultipleInstancesPolicy -cne 'IgnoreNew' -or $null -ne $t.Settings.RestartOnFailure){throw 'settings'}
 foreach($name in @('DisallowStartIfOnBatteries','StopIfGoingOnBatteries','RunOnlyIfIdle','RunOnlyIfNetworkAvailable')){if($t.Settings.$name -cne 'false'){throw 'condition'}}
 foreach($name in @('AllowStartOnDemand','Enabled')){if($t.Settings.$name -cne 'true'){throw 'disabled'}}
 if($t.RegistrationInfo.SecurityDescriptor -cne 'O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)'){throw 'security'}
 $script:registered=$true
}
try{
` + guestSetup[guardStart:guardEnd] + guestSetup[start:end] + `
}catch{$refused=$true}
[Console]::Out.Write((@{registered=$registered;refused=$refused}|ConvertTo-Json -Compress))`
		var facts struct{ Registered, Refused bool }
		out := runTestPS(t, script, input)
		if json.Unmarshal([]byte(out), &facts) != nil || facts.Registered == exists || facts.Refused != exists {
			t.Fatal("registration or preexistence refusal differs")
		}
	}
}

func TestRunnerTaskSanitation(t *testing.T) {
	stateStart, stateEnd := strings.Index(imageSanitize, " # Numeric Task Scheduler"), strings.Index(imageSanitize, " foreach($path in @('C:\\Windows'")
	cleanStart, cleanEnd := strings.Index(imageSanitize, " # No adapter delivery"), strings.Index(imageSanitize, " $marker=Join-Path")
	if stateStart < 0 || stateEnd <= stateStart || cleanStart < 0 || cleanEnd <= cleanStart {
		t.Fatal("sanitation blocks unavailable")
	}
	body := imageSanitize[stateStart:stateEnd] + imageSanitize[cleanStart:cleanEnd]
	body = strings.ReplaceAll(body, `'C:\ProgramData\Bivouac\Guest'`, "$d.guest")
	body = strings.ReplaceAll(body, `'C:\ProgramData\Bivouac\Agent'`, "$d.agent")
	body = strings.ReplaceAll(body, "exit 33", "throw 'runner state'")
	body = strings.ReplaceAll(body, "exit 1", "throw 'residue'")
	for _, mode := range []string{"ready", "running", "queued", "unknown", "unexpected"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			guest, agent := filepath.Join(root, "Guest"), filepath.Join(root, "Agent")
			for _, p := range []string{guest, agent} {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"launched", "launch-mode", "detached.claim", "cancelled", "jit", "lab-probe.json", "lab-grandchild.json", "lab-task-request.json", "lab-agent-request.json", "lab-task-complete.json", "lab-agent-complete.json"} {
				if err := os.WriteFile(filepath.Join(guest, name), []byte("public fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unexpected" {
				if err := os.WriteFile(filepath.Join(guest, "unexpected"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			state := 3
			switch mode {
			case "running":
				state = 4
			case "queued":
				state = 2
			case "unknown":
				state = 0
			}
			input, _ := json.Marshal(map[string]any{"guest": guest, "agent": agent, "state": state})
			script := `$ErrorActionPreference='Stop';$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$refused=$false;$tasks=[Collections.Generic.List[string]]::new()
function Get-ScheduledTask {param($TaskName,$ErrorAction) $tasks.Add($TaskName);[pscustomobject]@{State=$d.state}}
function Assert-Ordinary {param($Path) if((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'link'}}
try{
` + body + `
}catch{$refused=$true}
[Console]::Out.Write((@{refused=$refused;tasks=$tasks.ToArray()}|ConvertTo-Json -Compress))`
			var facts struct {
				Refused bool
				Tasks   []string
			}
			out := runTestPS(t, script, input)
			if json.Unmarshal([]byte(out), &facts) != nil || facts.Refused != (mode != "ready") {
				t.Fatal("sanitation refusal differs")
			}
			if mode == "ready" {
				if _, err := os.Stat(guest); !os.IsNotExist(err) {
					t.Fatal("guest launch residue remained")
				}
				if len(facts.Tasks) != 3 || facts.Tasks[1] != guestagent.WindowsTaskName || facts.Tasks[2] != guestagent.WindowsRunnerTaskName {
					t.Fatal("sanitation lost a task")
				}
			} else if mode != "unexpected" {
				if _, err := os.Stat(filepath.Join(guest, "launched")); err != nil {
					t.Fatal("active task state touched residue")
				}
			}
		})
	}
}

func TestPublicationRequiresBothTaskFacts(t *testing.T) {
	good := guestagent.TaskFacts{TaskUser: true, TaskHighest: true, TaskInteractive: true, TaskAction: true, TaskPriority: 4, TaskPolicy: true, TaskSecurity: true}
	for _, mode := range []string{"both", "missing agent", "missing runner", "invalid security", "autologon mismatch"} {
		m := Manifest{AgentTask: good, RunnerTask: good, AutologonAccountMatches: true}
		switch mode {
		case "autologon mismatch":
			m.AutologonAccountMatches = false
		case "missing agent":
			m.AgentTask = guestagent.TaskFacts{}
		case "missing runner":
			m.RunnerTask = guestagent.TaskFacts{}
		case "invalid security":
			m.RunnerTask.TaskSecurity = false
		}
		path := filepath.Join(t.TempDir(), "manifest.json")
		if m.tasksValid() != (mode == "both") {
			t.Fatal("publication task gate differs")
		}
		// Invalid facts must refuse before publication's administrator ACL work.
		if mode == "both" {
			continue
		}
		if err := publishManifest(path, m); err == nil {
			t.Fatal("publication admitted missing task proof")
		}
		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Fatal("invalid publication wrote metadata")
		}
	}
}
