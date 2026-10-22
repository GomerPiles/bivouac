//go:build windows

package imagefactory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineDriverTransactions(t *testing.T) {
	for _, mode := range []string{"nested", "hash", "missing", "unexpected", "existing", "link", "destination link"} {
		t.Run(mode, func(t *testing.T) {
			mount, snapshot := t.TempDir(), t.TempDir()
			source := filepath.Join(snapshot, "0")
			if err := os.MkdirAll(filepath.Join(source, "nested", "empty"), 0700); err != nil {
				t.Fatal(err)
			}
			content := []byte("public-driver-bytes")
			file := filepath.Join(source, "nested", "driver.dll")
			if err := os.WriteFile(file, content, 0600); err != nil {
				t.Fatal(err)
			}
			plan := []Driver{{Name: "display.inf_amd64_example", Directories: []string{"nested", `nested\empty`}, Files: map[string]string{`nested\driver.dll`: hashBytes(content)}}}
			target := filepath.Join(mount, "Windows", "System32", "HostDriverStore", "FileRepository", plan[0].Name)
			switch mode {
			case "hash":
				plan[0].Files[`nested\driver.dll`] = strings.Repeat("0", 64)
			case "missing":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			case "unexpected":
				if err := os.WriteFile(filepath.Join(source, "extra"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "existing":
				if err := os.MkdirAll(target, 0700); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := createDriverTestJunction(filepath.Join(source, "link"), t.TempDir()); err != nil {
					t.Fatal(err)
				}
			case "destination link":
				if err := createDriverTestJunction(filepath.Join(mount, "Windows"), t.TempDir()); err != nil {
					t.Fatal(err)
				}
			}
			encoded, err := encodeDriverPlan(plan)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(map[string]any{"mount": mount, "snapshot": snapshot, "plan": json.RawMessage(encoded)})
			script := offlinePayload + `
$ErrorActionPreference='Stop';$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$ok=$false;$line=0
try{Copy-OfflineDrivers $d.mount $d.snapshot $d.plan;$ok=$true}catch{$line=$_.InvocationInfo.ScriptLineNumber;$kind=$_.Exception.GetType().Name;$id=$_.FullyQualifiedErrorId.Split(',')[0]}
[Console]::Out.Write((@{ok=$ok;line=$line;kind=$kind;id=$id}|ConvertTo-Json -Compress))`
			var result struct {
				OK   bool
				Line int
				Kind string
				ID   string
			}
			if err := json.Unmarshal([]byte(runTestPS(t, script, data)), &result); err != nil {
				t.Fatal(err)
			}
			if result.OK != (mode == "nested") {
				t.Fatalf("transaction outcome, mode=%s line=%d kind=%s id=%s", mode, result.Line, result.Kind, result.ID)
			}
			if _, err := os.Lstat(target + ".bivouac-staging"); !os.IsNotExist(err) {
				t.Fatal("temporary tree remains")
			}
			if mode == "nested" {
				b, err := os.ReadFile(filepath.Join(target, "nested", "driver.dll"))
				if err != nil || string(b) != string(content) {
					t.Fatal("nested bytes missing")
				}
				if info, err := os.Stat(filepath.Join(target, "nested", "empty")); err != nil || !info.IsDir() {
					t.Fatal("empty directory missing")
				}
			} else if mode != "existing" {
				if _, err := os.Lstat(target); !os.IsNotExist(err) {
					t.Fatal("partial tree published")
				}
			}
		})
	}
}

func TestAgentImageScripts(t *testing.T) {
	for _, token := range []string{"Install-OfflineAgent", "$data.agent_sha256", "Copy-OfflineDrivers", "$data.driver_plan"} {
		if !strings.Contains(stageSetup, token) {
			t.Fatal("offline staging missing", token)
		}
	}
	for _, token := range []string{"Program Files\\Bivouac", "O:BAD:P", ";;;BU)", "Get-FileHash", "[IO.Directory]::Move($temporary,$target)", "$parentACL.GetOwner"} {
		if !strings.Contains(offlinePayload, token) {
			t.Fatal("offline plan missing", token)
		}
	}
	for _, token := range []string{"-LogonType Interactive -RunLevel Highest", "-AtLogOn -User $user", "-Priority 4", "-RestartCount 3", "-ExecutionTimeLimit ([TimeSpan]::Zero)", "-Execute $agent", "guest-agent --user ", "Start-ScheduledTask -TaskName 'bivouac-guest-agent'", "'/restart-device'"} {
		if !strings.Contains(guestSetup, token) {
			t.Fatal("agent setup missing", token)
		}
	}
	for _, token := range []string{"Remove-FixedService 'AppSandboxAgent'", "Remove-FixedService 'sshd'", "@('/x',$key.PSChildName", "Remove-BoundedTree 'C:\\ProgramData\\ssh'", "bivouac-hcs-ssh-hostkeys"} {
		if !strings.Contains(guestSpecialize, token) {
			t.Fatal("specialize removal missing", token)
		}
	}
	for _, script := range []string{guestValidate, imageSanitize, validateEntry, sanitizeEntry} {
		for _, token := range []string{"ssh", "appsandbox-agent", "gpu_query"} {
			if strings.Contains(strings.ToLower(script), token) {
				t.Fatal("legacy operation remains", token)
			}
		}
	}
}

func TestAgentInspectionFacts(t *testing.T) {
	root := t.TempDir()
	install := filepath.Join(root, "Program Files", "Bivouac")
	if err := os.MkdirAll(install, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, "bivouac.exe"), []byte("public-agent"), 0600); err != nil {
		t.Fatal(err)
	}
	task := filepath.Join(root, "Windows", "System32", "Tasks", "bivouac-guest-agent")
	if err := os.MkdirAll(filepath.Dir(task), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(task, nil, 0600); err != nil {
		t.Fatal(err)
	}
	facts := filesystemFacts(t, root)
	if !facts.AgentPresent || !facts.AgentTaskPresent || facts.AgentSHA256 != hashBytes([]byte("public-agent")) {
		t.Fatal("agent facts missing")
	}
	facts.SystemSetupInProgress, facts.OOBEInProgress = 1, 1
	facts.ImageStateKind, facts.UnattendPointerKind, facts.AnswerDirectoryEmpty = "generalized_to_oobe", "absent", true
	if facts.Eligible() {
		t.Fatal("installed agent accepted as template")
	}
	facts.AgentPresent = false
	if facts.Eligible() {
		t.Fatal("agent logon task accepted as template")
	}
}
