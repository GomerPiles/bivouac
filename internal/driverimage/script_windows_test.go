//go:build windows

package driverimage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOfflineCopyScriptWithMockStorage(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "bivouac-gpu-"+strings.Repeat("a", 32))
	payload := filepath.Join(workspace, "payload", "display.inf_package", "sub")
	if err := os.MkdirAll(payload, 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("immutable-driver")
	hash := sha256.Sum256(content)
	if err := os.WriteFile(filepath.Join(payload, "driver.dll"), content, 0600); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(workspace, "disk.vhdx")
	if err := os.WriteFile(disk, []byte("not-a-real-disk"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(workspace, "owner.json"), map[string]string{"workspace": workspace, "key": strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	const mock = `
function Get-DiskImage {param($ImagePath);[pscustomobject]@{Attached=$false}}
function Mount-DiskImage {param($ImagePath,$Access,[switch]$NoDriveLetter,[switch]$PassThru);[pscustomobject]@{Owned=$true}}
function Get-Disk {[pscustomobject]@{Number=73;IsReadOnly=$false;IsOffline=$false}}
function Get-Partition {param($DiskNumber);[pscustomobject]@{PartitionNumber=3;Size=100}}
function Add-PartitionAccessPath {param($DiskNumber,$PartitionNumber,$AccessPath);$null=New-Item -ItemType Directory -Path (Join-Path $AccessPath 'Windows\System32') -Force}
function Remove-PartitionAccessPath {param($DiskNumber,$PartitionNumber,$AccessPath);$expected=Join-Path $workspace 'mount';if([IO.Path]::GetFullPath($AccessPath.TrimEnd('\')) -cne $expected){throw 'unexpected test mount'};[IO.Directory]::Move($expected,(Join-Path $workspace 'captured'));$null=New-Item -ItemType Directory -Path $expected}
function Dismount-DiskImage {param($ImagePath)}
`
	script := filepath.Join(workspace, "mock.ps1")
	if err := os.WriteFile(script, []byte(mock+prepareScript), 0600); err != nil {
		t.Fatal(err)
	}
	packages := []Package{{Name: "display.inf_package", Files: []File{{Path: "sub/driver.dll", Size: int64(len(content)), SHA256: hex.EncodeToString(hash[:])}}}}
	data, _ := json.Marshal(struct {
		Workspace, Disk string
		Packages        []Package
	}{workspace, disk, packages})
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G702 -- Test-owned script mocks every mount operation and runs the real bounded copy script.
	cmd := exec.CommandContext(t.Context(), filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Stdin = bytes.NewReader(data)
	if err := cmd.Run(); err != nil {
		facts, _ := os.ReadFile(filepath.Join(workspace, "failure.json"))
		t.Fatal("copy script failed", err, string(facts))
	}
	actual, err := os.ReadFile(filepath.Join(workspace, "captured", "Windows", "System32", "HostDriverStore", "FileRepository", "display.inf_package", "sub", "driver.dll"))
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatal("offline copy differs", err)
	}
}
