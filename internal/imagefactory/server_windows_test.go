//go:build windows

package imagefactory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMSIUninstallPrecedesLeftoverServerRemoval(t *testing.T) {
	start := strings.Index(guestSpecialize, " $step=90;")
	end := strings.Index(guestSpecialize, " $step=92;")
	if start < 0 || end <= start {
		t.Fatal("server removal steps missing")
	}
	mock := `$ErrorActionPreference='Stop';$events=[Collections.Generic.List[string]]::new()
function Write-SetupStep {param($Code,$Failed)}
function Test-Path {param($LiteralPath) return $true}
function Get-ChildItem {param($LiteralPath) if($LiteralPath -like '*WOW6432Node*'){return};[pscustomobject]@{PSPath='fixture';PSChildName='{11111111-2222-3333-4444-555555555555}'}}
function Get-ItemProperty {param($LiteralPath) [pscustomobject]@{DisplayName='OpenSSH for Windows'}}
function Start-Process {param($FilePath,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru)
 if($ArgumentList[0] -ne '/x' -or $ArgumentList[1] -ne '{11111111-2222-3333-4444-555555555555}' -or $WindowStyle -ne 'Hidden'){throw 'uninstall arguments'}
 $events.Add('uninstall');[pscustomobject]@{ExitCode=0}
}
function Remove-FixedService {param($Name) if($Name -ne 'sshd'){throw 'client service touched'};$events.Add('server-service')}
function Remove-BoundedTree {param($Path) if($Path -notin @('C:\Program Files\OpenSSH','C:\Program Files\OpenSSH-Win64')){throw 'inbox client touched'};$events.Add('server-directory')}
`
	var events []string
	output := runTestPS(t, mock+guestSpecialize[start:end]+"\n"+`[Console]::Out.Write(($events.ToArray()|ConvertTo-Json -Compress))`, nil)
	if json.Unmarshal([]byte(output), &events) != nil || len(events) != 4 || events[0] != "uninstall" || events[1] != "server-service" {
		t.Fatal("MSI/service removal order changed")
	}
	if strings.Contains(guestSpecialize, "Remove-FixedService 'ssh-agent'") || strings.Contains(guestSpecialize, `'C:\Windows\System32\OpenSSH'`) {
		t.Fatal("inbox client removal remains")
	}
}

func TestFirstLogonRemovesOnlyServerCapability(t *testing.T) {
	start := strings.Index(guestSetup, "# The inbox client")
	end := strings.Index(guestSetup, "$step=40;")
	if start < 0 || end <= start {
		t.Fatal("server capability steps missing")
	}
	for _, mode := range []string{"installed", "absent", "pending reboot", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			input, _ := json.Marshal(map[string]string{"mode": mode})
			mock := `$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json;$script:removed=0;$ok=$true
function Write-SetupStep {param($Code,$Failed)}
function Get-WindowsCapability {param([switch]$Online,$Name)
 if($Name -cne 'OpenSSH.Server~~~~0.0.1.0'){throw 'wrong capability'}
 $state='NotPresent';if($data.mode -in @('installed','pending reboot') -and !$script:removed){$state='Installed'};if($data.mode -eq 'unknown'){$state='Unknown'}
 [pscustomobject]@{State=$state}
}
function Remove-WindowsCapability {param([switch]$Online,$Name)
 if($Name -cne 'OpenSSH.Server~~~~0.0.1.0'){throw 'wrong capability'}
 $script:removed++;[pscustomobject]@{RestartNeeded=($data.mode -eq 'pending reboot')}
}
try{
`
			output := runTestPS(t, mock+guestSetup[start:end]+"\n"+`}catch{$ok=$false};[Console]::Out.Write((@{ok=$ok;removed=$script:removed}|ConvertTo-Json -Compress))`, input)
			var result struct {
				OK      bool
				Removed int
			}
			if json.Unmarshal([]byte(output), &result) != nil || result.OK != (mode == "installed" || mode == "absent") || ((result.Removed == 1) != (mode == "installed" || mode == "pending reboot")) {
				t.Fatal("server capability removal decision")
			}
		})
	}
	for _, path := range []string{`C:\Windows\System32\OpenSSH\sshd.exe`, `C:\ProgramData\ssh`, `authorized_keys`, `administrators_authorized_keys`} {
		if !strings.Contains(guestSetup, path) {
			t.Fatal("missing server absence check")
		}
	}
}
