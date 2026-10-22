//go:build windows

package imagefactory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func filesystemFacts(t *testing.T, root string) Inspection {
	t.Helper()
	data, _ := json.Marshal(map[string]string{"root": root})
	script := "$ErrorActionPreference='Stop';" + (videoFacts + offlineFiles) + `
$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$f=@{};try{Read-FactoryFiles $d.root $f}catch{[Console]::Out.WriteLine($_.Exception.GetType().Name+":"+$_.InvocationInfo.ScriptLineNumber+":"+$_.FullyQualifiedErrorId.Split(',')[0]);exit 0}
[Console]::Out.Write(($f|ConvertTo-Json -Compress -Depth 5))`
	var facts Inspection
	out := runTestPS(t, script, data)
	if json.Unmarshal([]byte(out), &facts) != nil {
		t.Fatal("invalid filesystem facts", out)
	}
	return facts
}

func TestRunnerResidueBounds(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"actions-runner/bin", "actions-runner/_work", "actions-runner/_diag"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"bin/Runner.Listener.exe", "config.cmd", "run.cmd"} {
		if err := os.WriteFile(filepath.Join(root, "actions-runner", file), []byte("public-placeholder"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 65 {
		if err := os.WriteFile(filepath.Join(root, "actions-runner/_work", fmt.Sprintf("entry %02d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "actions-runner/_work/unlisted!"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	facts := filesystemFacts(t, root)
	work, diag := facts.RunnerResidue["_work"], facts.RunnerResidue["_diag"]
	if facts.RunnerState != "residue" || len(work.Entries) != 64 || !work.Truncated || work.OmittedNames != 1 || len(diag.Entries) != 0 {
		t.Fatal("residue bounds/counts lost")
	}
	for _, entry := range work.Entries {
		if entry.Directory || strings.Contains(entry.Name, "!") {
			t.Fatal("unsafe residue fact")
		}
	}
	// Marker presence takes precedence over residue; no marker contents are read.
	if err := os.WriteFile(filepath.Join(root, "actions-runner/.runner"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if filesystemFacts(t, root).RunnerState != "configured" {
		t.Fatal("registration marker missed")
	}
}

func TestPantherAnswerFacts(t *testing.T) {
	for _, name := range []string{"matching", "other user", "missing", "malformed", "dtd", "oversize"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "Windows/Panther")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			user := "imageuser"
			if name == "other user" {
				user = "otheruser"
			}
			text := `<unattend xmlns="urn:schemas-microsoft-com:unattend"><settings pass="specialize"/><settings pass="oobeSystem"><component><UserAccounts><LocalAccounts><LocalAccount><Name>` + user + `</Name></LocalAccount></LocalAccounts></UserAccounts><AutoLogon><Username>` + user + `</Username></AutoLogon></component></settings></unattend>`
			switch name {
			case "malformed":
				text = "<unattend>"
			case "dtd":
				text = `<!DOCTYPE unattend [<!ENTITY account "imageuser">]><unattend/>`
			case "oversize":
				text = strings.Repeat(" ", (1<<20)+1)
			}
			if name != "missing" {
				if err := os.WriteFile(filepath.Join(dir, "unattend.xml"), []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			data, _ := json.Marshal(map[string]string{"root": root, "user": "imageuser"})
			script := "$ErrorActionPreference='Stop';" + (videoFacts + offlineFiles) + `;$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$f=@{};Read-PantherAnswerFacts $d.root $d.user $f;[Console]::Out.Write(($f|ConvertTo-Json -Compress -Depth 5))`
			result := runTestPS(t, script, data)
			var facts Inspection
			if json.Unmarshal([]byte(result), &facts) != nil {
				t.Fatal("answer fact JSON")
			}
			if name != "matching" && name != "other user" {
				if facts.PantherAnswer != nil {
					t.Fatal("unknown answer facts reported as known")
				}
				return
			}
			fact := facts.PantherAnswer
			if fact == nil || !fact.SpecializePass || !fact.OOBESystemPass || !fact.AutologonPresent || fact.GuestLocalAccount != (name == "matching") || fact.AutologonGuestUser != (name == "matching") {
				t.Fatal("answer predicates incorrect")
			}
			if strings.Contains(result, user) || strings.Contains(result, "Username") {
				t.Fatal("answer values escaped")
			}
		})
	}
}

func TestInspectionOptionalHiveFailures(t *testing.T) {
	// All disk commands and offline hive calls are replaced. Only ordinary
	// temporary files are created, and no registry or mount API is dispatched.
	root := t.TempDir()
	id := strings.Repeat("b", 32)
	workspace := filepath.Join(root, id)
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "disk.vhdx"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	marker, _ := json.Marshal(map[string]string{"build_id": id, "workspace": workspace})
	if err := os.WriteFile(filepath.Join(workspace, "owner.json"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	start := strings.Index(inspectDisk, "@\"\n") + 3
	end := strings.Index(inspectDisk[start:], "\n\"@") + start
	if start < 3 || end < start {
		t.Fatal("inspection bindings missing")
	}
	bindings := `
using System;
public static class FactoryInspection {
 public static uint OROpenHive(string path,out IntPtr hive) {hive=new IntPtr(1);if(path.EndsWith("SAM"))throw new InvalidOperationException();return 0;}
 public static uint ORCloseHive(IntPtr hive) {return 0;}
 public static uint Number(IntPtr hive,string key,string value) {return 1;}
 public static string State(IntPtr hive) {return "generalized_to_oobe";}
 public static string Pointer(IntPtr hive) {return "absent";}
 public static bool Exists(IntPtr hive,string key) {throw new InvalidOperationException();}
 public static string Text(IntPtr hive,string key,string value) {return "";}
}
`
	mocks := `
function Get-DiskImage {param($ImagePath) [pscustomobject]@{Attached=$false}}
function Mount-DiskImage {param($ImagePath,$Access,[switch]$NoDriveLetter,[switch]$PassThru) [pscustomobject]@{Fake=$true}}
function Get-Disk {[pscustomobject]@{Number=123}}
function Get-Partition {param($DiskNumber) [pscustomobject]@{PartitionNumber=2;Size=100}}
function Add-PartitionAccessPath {param($DiskNumber,$PartitionNumber,$AccessPath)
 foreach($part in @('Windows\Panther','Windows\System32\config')){$null=New-Item -ItemType Directory -Path (Join-Path $AccessPath $part) -Force}
 foreach($part in @('SYSTEM','SOFTWARE','SAM')){[IO.File]::WriteAllText((Join-Path $AccessPath ('Windows\System32\config\'+$part)),'public-placeholder')}
}
function Remove-PartitionAccessPath {param($DiskNumber,$PartitionNumber,$AccessPath)
 foreach($part in @('Windows\System32\config\SYSTEM','Windows\System32\config\SOFTWARE','Windows\System32\config\SAM','Windows\System32\config','Windows\System32','Windows\Panther','Windows')){$null=Remove-Item -LiteralPath (Join-Path $AccessPath $part)}
}
function Dismount-DiskImage {param($ImagePath)}
`
	script := mocks + (videoFacts + offlineFiles) + inspectDisk[:start] + bindings + inspectDisk[end:]
	path := filepath.Join(workspace, "fake-inspection.ps1")
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]string{"root": root, "instance_id": id, "disk": filepath.Join(workspace, "disk.vhdx"), "guest_user": "imageuser"})
	b, err := executeHost(t.Context(), path, data, true)
	var facts Inspection
	if err != nil || json.Unmarshal(b, &facts) != nil || !facts.Eligible() || facts.GuestUserExists != nil || facts.VDDPresent != nil {
		t.Fatal("informational hive failure blocked inspection or became a known fact")
	}
}
