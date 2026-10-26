//go:build windows

package guestagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
		"missing setting":   {"<AllowStartOnDemand>true</AllowStartOnDemand>", ""},
		"duplicate section": {"</Task>", "<Settings/></Task>"},
		"owner":             {"O:SY", "O:BU"}, "unprotected": {"D:P", "D:"},
		"user ace":    {"</SecurityDescriptor>", "(A;;FRFX;;;BU)</SecurityDescriptor>"},
		"admin write": {"FRFX", "FA"}, "system reduced": {"FA;;;SY", "FRFX;;;SY"},
		"dacl missing": {"O:SYD:P(A;;FA;;;SY)(A;;FRFX;;;BA)", ""},
	}
	check := func(raw string) bool {
		f, err := taskFacts([]byte(raw), WindowsRunnerTaskName, "imageuser", "S-1-5-21-1-2-3-1001", func(name string) string {
			if name == "imageuser" {
				return "S-1-5-21-1-2-3-1001"
			}
			return ""
		})
		return err == nil && f.Valid()
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
	for _, mode := range []string{"missing", "ordinary", "hardlink"} {
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
