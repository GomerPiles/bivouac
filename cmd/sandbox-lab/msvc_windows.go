//go:build windows

package main

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/wintools"
	"golang.org/x/sys/windows"
)

//go:embed msvc-layout.ps1
var msvcLayoutScript string

func msvcBootstrapRecipe() wintools.Recipe {
	// Downloaded from Microsoft's VS 2022 Current bootstrapper endpoint; the
	// pinned file additionally requires a valid timestamped Microsoft signature
	// inside the setup guest before execution. No installer runs on the host.
	return wintools.Recipe{Bytes: 4474120, SHA256: "4aad1082e180f558598c346eb105b465b4908148cb9f7f0511aa1105620e0c30"}
}

type msvcLayoutFacts struct {
	Identity          labRecord       `json:"identity"`
	Stage             int             `json:"stage"`
	Complete          bool            `json:"complete"`
	Failed            bool            `json:"failed"`
	ExitCode          int64           `json:"exit_code"`
	BootstrapVerified bool            `json:"bootstrap_verified"`
	Files             uint32          `json:"files"`
	Bytes             uint64          `json:"bytes"`
	ElapsedMS         int64           `json:"elapsed_ms"`
	Errors            map[string]bool `json:"errors"`
	Frames            []string        `json:"frames"`
}

func (f msvcLayoutFacts) valid(record labRecord) bool {
	if !sameGuest(f.Identity, record) || f.Stage < 1 || f.Stage > 4 || f.Files > 20000 || f.Bytes > 20<<30 || f.ElapsedMS < 0 || f.ElapsedMS > 260000 || len(f.Errors) != 7 || len(f.Frames) > 16 || f.ExitCode < -1<<31 || f.ExitCode > 1<<32-1 {
		return false
	}
	for _, frame := range f.Frames {
		if len(frame) > 190 || (!strings.HasPrefix(frame, "System.") && !strings.HasPrefix(frame, "Microsoft.")) || strings.Trim(frame, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.+<>`") != "" {
			return false
		}
	}
	for _, name := range []string{"file_missing", "file_load", "io", "access_denied", "not_supported", "web", "invalid_operation"} {
		if _, ok := f.Errors[name]; !ok {
			return false
		}
	}
	return !f.Complete || (f.Stage == 4 && !f.Failed && f.ExitCode == 0 && f.BootstrapVerified && f.Files > 0 && f.Bytes > 0)
}

func startGuestMSVCLayout(ctx context.Context) error {
	if !session().valid() {
		return errors.New("MSVC layout guest context refused")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return errors.New("guest layout task system directory unavailable")
	}
	// The fixed task decouples a bounded setup process from the CLI's 30 s
	// dispatch deadline. Guest deletion ends remaining installer descendants.
	const script = `$ErrorActionPreference='Stop';if(Get-ScheduledTask -TaskName 'bivouac-sandbox-msvc-layout' -ErrorAction SilentlyContinue){throw 'existing layout task'};$a=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\BivouacBootstrap\msvc-layout.ps1';$p=New-ScheduledTaskPrincipal -UserId 'WDAGUtilityAccount' -LogonType Interactive -RunLevel Highest;$s=New-ScheduledTaskSettingsSet -Priority 7 -ExecutionTimeLimit (New-TimeSpan -Minutes 5);Register-ScheduledTask -TaskName 'bivouac-sandbox-msvc-layout' -Action $a -Principal $p -Settings $s | Out-Null;Start-ScheduledTask -TaskName 'bivouac-sandbox-msvc-layout'`
	cmd := exec.CommandContext(ctx, filepath.Join(system, `WindowsPowerShell\v1.0\powershell.exe`), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if cmd.Run() != nil {
		return errors.New("guest layout task unavailable")
	}
	return nil
}

func (h *labHost) msvcLayoutProbe(ctx context.Context, result *labResult) error {
	data, err := h.call(ctx, "exec", "--id", h.record.ID, "--command", `"C:\Program Files\Bivouac\sandbox-lab.exe" start-msvc-layout`, "--run-as", "ExistingLogin")
	var receipt struct {
		Exit *int `json:"ExitCode"`
	}
	if err != nil || decodeBounded(bytes.NewReader(data), &receipt) != nil || receipt.Exit == nil || *receipt.Exit != 0 {
		return errors.New("guest layout dispatch unproven")
	}
	wait, cancel := context.WithTimeout(ctx, 260*time.Second)
	defer cancel()
	var facts msvcLayoutFacts
	for readJSON(filepath.Join(h.output, "msvc-layout-result.json"), &facts) != nil {
		if pause(wait) != nil {
			return errors.New("guest layout deadline; partial public payloads retained")
		}
	}
	if !facts.valid(h.record) {
		return errors.New("guest layout report refused")
	}
	result.MSVCLayout = &facts
	if !facts.Complete || facts.Failed || !facts.BootstrapVerified || facts.ExitCode != 0 || facts.Stage != 4 {
		return errors.New("MSVC offline layout incomplete; not an installable tool profile")
	}
	return nil
}
