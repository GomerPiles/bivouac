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
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed baseline.ps1
var baselineScript string

type baselineFacts struct {
	Identity     labRecord `json:"identity"`
	WindowsBuild uint32    `json:"windows_build"`
	Defender     struct {
		CommandPresent  bool `json:"command_present"`
		Observed        bool `json:"observed"`
		ServiceEnabled  bool `json:"service_enabled"`
		RealtimeEnabled bool `json:"realtime_enabled"`
		TamperProtected bool `json:"tamper_protected"`
	} `json:"defender"`
	Services map[string]struct {
		Present bool `json:"present"`
		Running bool `json:"running"`
	} `json:"services"`
	Tools              map[string]bool `json:"tools"`
	WindowsSDKVersions []string        `json:"windows_sdk_versions"`
}

func (f baselineFacts) valid(record labRecord) bool {
	if !sameGuest(f.Identity, record) || f.WindowsBuild == 0 || len(f.Services) != 5 || len(f.Tools) != 13 || len(f.WindowsSDKVersions) > 16 {
		return false
	}
	for _, name := range []string{"WinDefend", "WSearch", "wuauserv", "SysMain", "Sense"} {
		if _, ok := f.Services[name]; !ok {
			return false
		}
	}
	for _, name := range []string{"pwsh", "git", "7zip", "cmake", "ninja", "python", "node", "dotnet", "llvm", "runner_node", "msvc", "msbuild", "windows_sdk"} {
		if _, ok := f.Tools[name]; !ok {
			return false
		}
	}
	for _, version := range f.WindowsSDKVersions {
		if len(version) < 1 || len(version) > 32 || strings.Trim(version, "0123456789.") != "" {
			return false
		}
	}
	return true
}

func guestBaseline(ctx context.Context) error {
	if !session().valid() {
		return errors.New("guest baseline context refused")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return errors.New("guest baseline system path unavailable")
	}
	command := exec.CommandContext(ctx, filepath.Join(system, `WindowsPowerShell\v1.0\powershell.exe`), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", filepath.Join(bootstrapDirectory, "baseline.ps1"))
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if command.Run() != nil {
		return errors.New("guest baseline unavailable")
	}
	return nil
}

func (h *labHost) baselineProbe(ctx context.Context, result *labResult) error {
	data, err := h.call(ctx, "exec", "--id", h.record.ID, "--command", `"C:\Program Files\Bivouac\sandbox-lab.exe" guest-baseline`, "--run-as", "ExistingLogin")
	var receipt struct {
		Exit *int `json:"ExitCode"`
	}
	if err != nil || decodeBounded(bytes.NewReader(data), &receipt) != nil || receipt.Exit == nil || *receipt.Exit != 0 {
		return errors.New("guest baseline dispatch unproven")
	}
	var facts baselineFacts
	if readJSON(filepath.Join(h.output, "baseline.json"), &facts) != nil || !facts.valid(h.record) {
		return errors.New("guest baseline predicates unproven")
	}
	result.Baseline = &facts
	return nil
}

func labMemoryAvailable(reserveMB uint64) bool {
	var status struct {
		Length, Load                                                                                                          uint32
		TotalPhysical, AvailablePhysical, TotalPageFile, AvailablePageFile, TotalVirtual, AvailableVirtual, AvailableExtended uint64
	}
	status.Length = uint32(unsafe.Sizeof(status))
	// #nosec G103 -- Fixed MEMORYSTATUSEX output. No host state is changed.
	ok, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx").Call(uintptr(unsafe.Pointer(&status)))
	return ok != 0 && reserveMB <= 1<<30 && status.AvailablePhysical>>20 >= 4096+reserveMB
}
