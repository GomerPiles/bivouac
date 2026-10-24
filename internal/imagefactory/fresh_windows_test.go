//go:build windows

package imagefactory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Run only the real offline answer staging fragment on ordinary temp files.
// No administrator gate, mount API, registry query or guest code is executed.
func TestFreshOfflineAnswerStaging(t *testing.T) {
	bindingStart := strings.Index(stageSetup, "@\"\n") + 3
	bindingEnd := strings.Index(stageSetup[bindingStart:], "\n\"@") + bindingStart
	start := strings.Index(stageSetup, "  $phaseCode=60\n")
	end := strings.Index(stageSetup, "  $phaseCode=64\n")
	checkStart := strings.Index(stageSetup, "  $phaseCode=40\n")
	checkEnd := strings.Index(stageSetup, "  $phaseCode=50\n")
	prefixEnd := strings.Index(stageSetup, "\ntry {")
	if bindingStart < 3 || bindingEnd < bindingStart || start < 0 || end <= start || checkStart < 0 || checkEnd <= checkStart || prefixEnd < 0 {
		t.Fatal("offline staging fragment missing")
	}
	const descriptor = "'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'"
	fragment := stageSetup[checkStart:checkEnd] + stageSetup[start:end]
	if strings.Count(fragment, descriptor) != 1 {
		t.Fatal("protected answer DACL changed")
	}
	// The unelevated fixture substitutes its own SID for Administrators so
	// real DACL protection remains writable/testable without elevating.
	fragment = strings.Replace(fragment, descriptor, "$testDACL", 1)
	for _, mode := range []string{"absent", "empty answer", "nonempty answer", "Panther link", "Scripts link", "Panther file"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{`Windows\Setup`, `Windows\System32\config`, "Program Files", "ProgramData"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, `Windows\System32\config\SYSTEM`), []byte("public-placeholder"), 0600); err != nil {
				t.Fatal(err)
			}
			answer := filepath.Join(root, `Windows\Panther\Unattend`)
			switch mode {
			case "empty answer", "nonempty answer":
				if err := os.MkdirAll(answer, 0700); err != nil {
					t.Fatal(err)
				}
				if mode == "nonempty answer" {
					if err := os.WriteFile(filepath.Join(answer, "unexpected"), []byte("keep"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "Panther link", "Scripts link":
				path := filepath.Join(root, `Windows\Panther`)
				if mode == "Scripts link" {
					path = filepath.Join(root, `Windows\Setup\Scripts`)
				}
				if err := createDriverTestJunction(path, t.TempDir()); err != nil {
					t.Fatal(err)
				}
			case "Panther file":
				if err := os.WriteFile(filepath.Join(root, `Windows\Panther`), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			prefix := stageSetup[:prefixEnd]
			script := offlinePayload + prefix + "\n$null=Add-Type -TypeDefinition @\"\n" + stageSetup[bindingStart:bindingEnd] + "\n\"@\n" + `
$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$mount=$d.root;$data=@{specialize='public-script';unattend='public-answer'};$ok=$false;$ordinary=$false;$private=$false
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$testDACL='D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+$sid+')'
[IO.File]::SetAttributes((Join-Path $mount 'ProgramData'),([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::Hidden))
try{
` + fragment + `
 $ordinary=$true
 foreach($relative in @('Windows\Panther','Windows\Setup\Scripts')){
  $path=Join-Path $mount $relative;$a=Get-Acl -LiteralPath $path;$p=Get-Acl -LiteralPath (Split-Path -Parent $path)
  if(!$a.GetOwner([Security.Principal.SecurityIdentifier]).Equals($p.GetOwner([Security.Principal.SecurityIdentifier])) -or $a.AreAccessRulesProtected -or @($a.Access|Where-Object {!$_.IsInherited}).Count){$ordinary=$false}
 }
 $a=Get-Acl -LiteralPath $answerDirectory
 $private=$a.AreAccessRulesProtected -and $a.Access.Count -eq 2 -and @($a.Access|Where-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18',$sid)}).Count -eq 0
 $ok=$true
}catch{}
[Console]::Out.Write((@{ok=$ok;ordinary=$ordinary;private=$private}|ConvertTo-Json -Compress))`
			input, _ := json.Marshal(map[string]string{"root": root})
			var result struct{ OK, Ordinary, Private bool }
			if err := json.Unmarshal([]byte(runTestPS(t, script, input)), &result); err != nil {
				t.Fatal(err)
			}
			want := mode == "absent" || mode == "empty answer"
			if result.OK != want || (want && (!result.Ordinary || !result.Private)) {
				t.Fatal("answer staging outcome or guest directory security")
			}
			if want {
				for _, file := range []string{"specialize.ps1", "unattend.xml"} {
					if _, err := os.Stat(filepath.Join(answer, file)); err != nil {
						t.Fatal(err)
					}
				}
				// CreateNew must refuse retrying the staged answer.
				if json.Unmarshal([]byte(runTestPS(t, script, input)), &result) != nil || result.OK {
					t.Fatal("staged answer reused")
				}
			}
		})
	}
}

func TestFreshOfflineDirectoryParents(t *testing.T) {
	for _, mode := range []string{"absent", "repository file", "store link"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			system := filepath.Join(root, `Windows\System32`)
			if err := os.MkdirAll(system, 0700); err != nil {
				t.Fatal(err)
			}
			store := filepath.Join(system, "HostDriverStore")
			switch mode {
			case "store link":
				if err := createDriverTestJunction(store, t.TempDir()); err != nil {
					t.Fatal(err)
				}
			case "repository file":
				if err := os.Mkdir(store, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(store, "FileRepository"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			input, _ := json.Marshal(map[string]string{"root": root})
			out := runTestPS(t, offlinePayload+`
$ErrorActionPreference='Stop';$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$ok=$false
try{
 $programData=Join-Path $d.root 'ProgramData'
 $null=New-Item -ItemType Directory -Path $programData
 [IO.File]::SetAttributes($programData,([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::Hidden))
 Copy-OfflineDrivers $d.root $d.root @()
 foreach($relative in @('Windows\System32\HostDriverStore','Windows\System32\HostDriverStore\FileRepository','ProgramData\Bivouac\Image')){
  $path=Join-Path $d.root $relative;New-OfflineDirectory $d.root $path
  $acl=Get-Acl -LiteralPath $path;$parent=Get-Acl -LiteralPath (Split-Path -Parent $path)
  if(!$acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($parent.GetOwner([Security.Principal.SecurityIdentifier])) -or $acl.AreAccessRulesProtected -or @($acl.Access|Where-Object {!$_.IsInherited}).Count){throw 'inheritance'}
 }
 $ok=$true
}catch{}
[Console]::Out.Write($ok.ToString())`, input)
			if (out == "True") != (mode == "absent") {
				t.Fatal("missing directory creation or ordinary-directory refusal")
			}
		})
	}
}
