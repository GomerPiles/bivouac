//go:build windows

package guestagent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTaskSchemaDefaults(t *testing.T) {
	for name, required := range map[string]string{"AllowStartOnDemand": "true", "Enabled": "true", "RunOnlyIfIdle": "false", "RunOnlyIfNetworkAvailable": "false", "MultipleInstancesPolicy": "IgnoreNew", "Priority": "4", "ExecutionTimeLimit": "PT0S", "DisallowStartIfOnBatteries": "false", "StopIfGoingOnBatteries": "false"} {
		t.Run(name, func(t *testing.T) {
			explicit := "<" + name + ">" + required + "</" + name + ">"
			defaultsCorrect := name != "Priority" && name != "ExecutionTimeLimit" && name != "DisallowStartIfOnBatteries" && name != "StopIfGoingOnBatteries"
			for _, absent := range []bool{false, true} {
				raw := runnerTaskXML
				if absent {
					raw = strings.ReplaceAll(raw, explicit, "")
				}
				f, err := taskFacts([]byte(raw), WindowsRunnerTaskName, "imageuser", "S-1-5-21-1-2-3-1001", func(string) string { return "" })
				if (err == nil && f.ValidDefinition()) != (!absent || defaultsCorrect) {
					t.Fatal("schema default decision differs", absent)
				}
			}
		})
	}
}

func TestRunnerTaskSecuritySeparateFromRuntimeDefinition(t *testing.T) {
	good := "O:SYD:P(A;;FA;;;SY)(A;;FRFX;;;BA)"
	for _, text := range []string{good, "", strings.ReplaceAll(good, "O:SY", "O:BU"), strings.ReplaceAll(good, "D:P", "D:"), good + "(A;;FRFX;;;BU)", strings.ReplaceAll(good, "FRFX", "FA"), strings.ReplaceAll(good, "FA;;;SY", "FRFX;;;SY")} {
		if runnerTaskSecurity(text) != (text == good) {
			t.Fatal("unexpected installation DACL decision")
		}
		raw := strings.ReplaceAll(runnerTaskXML, good, text)
		f, err := taskFacts([]byte(raw), WindowsRunnerTaskName, "imageuser", "S-1-5-21-1-2-3-1001", func(string) string { return "" })
		if err != nil || !f.ValidDefinition() || f.TaskSecurity {
			t.Fatal("runtime definition inspected the descriptor")
		}
	}
}

func TestInspectReportsEachTaskOnQueryFailure(t *testing.T) {
	good := TaskFacts{TaskUser: true, TaskHighest: true, TaskInteractive: true, TaskAction: true, TaskPriority: 4, TaskPolicy: true, TaskSecurity: true}
	for _, failed := range []string{WindowsTaskName, WindowsRunnerTaskName, "descriptor"} {
		var calls []string
		f := inspectTaskFacts(func(name string) (TaskFacts, error) {
			calls = append(calls, name)
			if name == failed {
				return TaskFacts{}, errors.New("private query failure")
			}
			if failed == "descriptor" && name == WindowsRunnerTaskName {
				return good, errors.New("private descriptor failure")
			}
			return good, nil
		})
		if len(calls) != 2 || f.Valid() {
			t.Fatal("failed task query was hidden")
		}
		if failed == WindowsTaskName {
			if f.TaskUser || !f.RunnerTask.Valid() {
				t.Fatal("runner facts lost")
			}
		} else if !f.TaskUser || f.RunnerTask.TaskSecurity {
			t.Fatal("agent facts lost or failed runner accepted")
		}
		if failed == "descriptor" && !f.RunnerTask.ValidDefinition() {
			t.Fatal("structural facts lost after DACL failure")
		}
	}
}

const runnerTaskXML = `<Task><RegistrationInfo><SecurityDescriptor>O:SYD:P(A;;FA;;;SY)(A;;FRFX;;;BA)</SecurityDescriptor></RegistrationInfo><Triggers/><Principals><Principal><UserId>S-1-5-21-1-2-3-1001</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><Priority>4</Priority><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><RunOnlyIfIdle>false</RunOnlyIfIdle><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries></Settings><Actions><Exec><Command>C:\Program Files\Bivouac\bivouac.exe</Command><Arguments>guest windows detached</Arguments><WorkingDirectory>C:\ProgramData\Bivouac\Guest</WorkingDirectory></Exec></Actions></Task>`

func TestRunnerTaskDefinitionRefusals(t *testing.T) {
	tests := map[string][2]string{
		"principal":   {"S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"},
		"interactive": {"InteractiveToken", "Password"}, "highest": {"HighestAvailable", "LeastPrivilege"},
		"priority": {"<Priority>4", "<Priority>7"}, "time": {"PT0S", "PT72H"}, "instances": {"IgnoreNew", "Parallel"},
		"demand": {"<AllowStartOnDemand>true", "<AllowStartOnDemand>false"}, "enabled": {"<Enabled>true", "<Enabled>false"},
		"idle": {"<RunOnlyIfIdle>false", "<RunOnlyIfIdle>true"}, "network": {"<RunOnlyIfNetworkAvailable>false", "<RunOnlyIfNetworkAvailable>true"},
		"battery start": {"<DisallowStartIfOnBatteries>false", "<DisallowStartIfOnBatteries>true"}, "battery stop": {"<StopIfGoingOnBatteries>false", "<StopIfGoingOnBatteries>true"},
		"path": {"C:\\Program Files\\Bivouac\\bivouac.exe", "C:\\other.exe"}, "argv": {"guest windows detached", "guest windows listener"},
		"working directory":  {"C:\\ProgramData\\Bivouac\\Guest", "C:\\Elsewhere"},
		"trigger":            {"<Triggers/>", "<Triggers><LogonTrigger/></Triggers>"},
		"duplicate triggers": {"<Triggers/>", "<Triggers/><Triggers/>"},
		"non exec":           {"</Actions>", "<ComHandler/></Actions>"}, "second exec": {"</Actions>", "<Exec/></Actions>"},
		"restart":           {"</Settings>", "<RestartOnFailure/></Settings>"},
		"duplicate setting": {"</Settings>", "<Enabled>true</Enabled></Settings>"},

		"duplicate section": {"</Task>", "<Settings/></Task>"},
	}
	check := func(raw string) bool {
		f, err := taskFacts([]byte(raw), WindowsRunnerTaskName, "imageuser", "S-1-5-21-1-2-3-1001", func(name string) string {
			if name == "imageuser" {
				return "S-1-5-21-1-2-3-1001"
			}
			return ""
		})
		return err == nil && f.ValidDefinition()
	}
	if !check(runnerTaskXML) || !check(strings.ReplaceAll(runnerTaskXML, "S-1-5-21-1-2-3-1001", "imageuser")) {
		t.Fatal("valid runner task refused")
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(runnerTaskXML, change[0]) {
				t.Fatal("fixture mutation missing")
			}
			if check(strings.ReplaceAll(runnerTaskXML, change[0], change[1])) {
				t.Fatal("unsafe runner task admitted")
			}
		})
	}
	for _, raw := range []string{runnerTaskXML + runnerTaskXML, "<!DOCTYPE Task>" + runnerTaskXML, strings.Repeat(" ", 65537), strings.Repeat("<a>", 18) + strings.Repeat("</a>", 18), "<Task>"} {
		if check(raw) {
			t.Fatal("unbounded or malformed task admitted")
		}
	}
	for _, name := range []string{WindowsTaskName, WindowsRunnerTaskName} {
		f, err := taskFacts([]byte(strings.ReplaceAll(runnerTaskXML, "</Actions>", "<ComHandler/></Actions>")), name, "imageuser", "sid", func(string) string { return "sid" })
		if err == nil && f.TaskAction {
			t.Fatal("non-Exec action disappeared")
		}
	}
}

func TestPinnedHelperRefusesMissingAndLinks(t *testing.T) {
	for _, mode := range []string{"missing", "ordinary", "hardlink", "junction"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			if mode != "missing" {
				if err := os.WriteFile(filepath.Join(directory, "bivouac.exe"), []byte("public helper fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "hardlink" {
				if err := os.Link(filepath.Join(directory, "bivouac.exe"), filepath.Join(directory, "alias.exe")); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "junction" {
				if err := os.Remove(filepath.Join(directory, "bivouac.exe")); err != nil {
					t.Fatal(err)
				}
				if err := createTestJunction(filepath.Join(directory, "bivouac.exe"), t.TempDir()); err != nil {
					t.Fatal(err)
				}
			}
			// Ancestor pinning/ACLs have receiver coverage. Exercise the same
			// ordinary-file open without needing host ancestor handle rights.
			pin := GuestDirectoryPin{&guestDir{path: directory}}
			defer func() { _ = pin.Close() }()
			file, err := pin.OpenHelper()
			if file != nil {
				_ = file.Close()
			}
			if (err == nil) != (mode == "ordinary") {
				t.Fatal("helper file safety differs")
			}
		})
	}
}
