//go:build windows

package control

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Only test-owned processes enter this job. No manager, guest, credential or
// installed task is involved in either the reproduction or the regression.
func TestPortableManagerJobLifetime(t *testing.T) {
	if os.Getenv("BIVOUAC_PORTABLE_JOB_FIXTURE") != "" {
		portableJobFixture(t)
		return
	}
	for _, mode := range []string{"inheritance", "guard"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			job, err := windows.CreateJobObject(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if job != 0 {
					_ = windows.CloseHandle(job)
				}
			})
			limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
			limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
			// #nosec G103 -- Fixed native structure, used only for the private fixture job.
			if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestPortableManagerJobLifetime$")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			cmd.Env = append(os.Environ(), "BIVOUAC_PORTABLE_JOB_FIXTURE="+mode, "BIVOUAC_PORTABLE_JOB_DIR="+dir)
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			pid := cmd.Process.Pid
			if pid < 1 || uint64(pid) > 0xffffffff {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal("invalid private fixture PID")
			}
			// #nosec G115 -- The positive test-child PID is bounded to uint32 above.
			process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
			if err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal(err)
			}
			err = windows.AssignProcessToJobObject(job, process)
			_ = windows.CloseHandle(process)
			if err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "assigned"), nil, 0o600); err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("private job fixture: %v: %s", err, output.Bytes())
			}
			if mode == "guard" {
				return
			}
			data, err := os.ReadFile(filepath.Join(dir, "child.pid"))
			if err != nil {
				t.Fatal(err)
			}
			childPID, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
			if err != nil {
				t.Fatal(err)
			}
			child, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(childPID))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = windows.CloseHandle(child) }()
			if state, err := windows.WaitForSingleObject(child, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
				t.Fatalf("hidden child did not survive its shell: %d, %v", state, err)
			}
			if err := windows.CloseHandle(job); err != nil {
				t.Fatal(err)
			}
			job = 0
			if state, err := windows.WaitForSingleObject(child, 5000); err != nil || state != windows.WAIT_OBJECT_0 {
				t.Fatalf("hidden child escaped the enclosing job: %d, %v", state, err)
			}
		})
	}
}

func portableJobFixture(t *testing.T) {
	t.Helper()
	dir := os.Getenv("BIVOUAC_PORTABLE_JOB_DIR")
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "assigned")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("parent never assigned the private job")
		}
		time.Sleep(20 * time.Millisecond)
	}
	script := `param([string]$Source)
$ErrorActionPreference='Stop'
if ($env:BIVOUAC_PORTABLE_JOB_FIXTURE -eq 'inheritance') {
    $child=Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 60') -WindowStyle Hidden -PassThru
    [IO.File]::WriteAllText((Join-Path $env:BIVOUAC_PORTABLE_JOB_DIR 'child.pid'),[string]$child.Id)
    exit 0
}
$tokens=$null
$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Portable control script did not parse' }
$guard=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-ManagerLaunchContext'},$true)
if (!$guard) { throw 'Manager context guard missing' }
. ([scriptblock]::Create($guard.Extent.Text))
try { Assert-ManagerLaunchContext } catch {
    if ($_.Exception.Message -like 'Cannot start a persistent manager inside a Windows process job*') { exit 0 }
    throw
}
throw 'Manager launch accepted an inherited Windows job'
`
	path := filepath.Join(dir, "fixture.ps1")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	control, err := filepath.Abs(filepath.Join("..", "..", "tools", "windows", "Control.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	// #nosec G702 -- Fixed system PowerShell executes only the private fixture script with argument-array paths.
	cmd := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path, control)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("portable PowerShell fixture: %v: %s", err, output)
	}
}
