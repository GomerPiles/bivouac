//go:build windows

package appsandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestControlScriptParsesInStockWindowsPowerShell(t *testing.T) {
	directory := t.TempDir()
	control := filepath.Join(directory, "control.ps1")
	parser := filepath.Join(directory, "parse.ps1")
	if err := os.WriteFile(control, []byte(windowsControl+"\n"+windowsJobHook+"\n"+windowsJobCompletedHook), 0o600); err != nil {
		t.Fatal(err)
	}
	const inspect = `param([string]$SourcePath)
$tokens=$null
$errors=$null
$null=[System.Management.Automation.Language.Parser]::ParseFile($SourcePath,[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){foreach($item in $errors){Write-Output $item.Message};exit 1}
`
	if err := os.WriteFile(parser, []byte(inspect), 0o600); err != nil {
		t.Fatal(err)
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
	// Stock Windows PowerShell can take many seconds to start on a loaded
	// hosted runner; the bound only stops a hung parser.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// #nosec G702 -- Fixed system parser command reads only a test-owned source file; the bootstrap is never executed.
	cmd := exec.CommandContext(ctx, binary, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", parser, control)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("stock Windows PowerShell did not finish parsing within the deadline: %v: %s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("stock Windows PowerShell rejected the guest control syntax: %v: %s", err, output)
	}
}
