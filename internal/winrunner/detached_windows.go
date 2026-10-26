//go:build windows

package winrunner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"golang.org/x/sys/windows"
)

func runnerChildCommand(binary, mode string) *exec.Cmd {
	cmd := exec.Command(binary, "guest", "windows", mode)
	cmd.Dir = guestBase
	// Ordinary child of the runner task, with independent NUL streams.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.DETACHED_PROCESS}
	return cmd
}

func runnerTaskCommand(ctx context.Context) (*exec.Cmd, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, errors.New("runner task unavailable")
	}
	cmd := exec.CommandContext(ctx, filepath.Join(system, "schtasks.exe"), "/Run", "/TN", guestagent.WindowsRunnerTaskName)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd, nil
}

func dispatchRunner(ctx context.Context, root *os.Root, mode string) error {
	return startChecked(root, mode, func() error { return guestagent.CheckRunnerTask(ctx) }, func() error {
		cmd, err := runnerTaskCommand(ctx)
		if err != nil {
			return err
		}
		if cmd.Run() != nil {
			return errors.New("runner task dispatch failed")
		}
		return nil
	})
}

func runnerDesktop() bool {
	session, _, err := interactiveDesktop()
	if err != nil || session != windows.WTSGetActiveConsoleSessionId() {
		return false
	}
	dll := windows.NewLazySystemDLL("user32.dll")
	station, _, _ := dll.NewProc("GetProcessWindowStation").Call()
	desktop, _, _ := dll.NewProc("GetThreadDesktop").Call(uintptr(windows.GetCurrentThreadId()))
	name := func(handle uintptr) string {
		var value [256]uint16
		var needed uint32
		// #nosec G103 -- Fixed bounded UOI_NAME output, borrowed user32 handles.
		ok, _, _ := dll.NewProc("GetUserObjectInformationW").Call(handle, 2, uintptr(unsafe.Pointer(&value[0])), uintptr(len(value)*2), uintptr(unsafe.Pointer(&needed)))
		if ok == 0 || needed > uint32(len(value)*2) {
			return ""
		}
		return windows.UTF16ToString(value[:])
	}
	return name(station) == "WinSta0" && name(desktop) == "Default"
}

func guestDetached(ctx context.Context) error {
	self, err := os.Executable()
	if err != nil || !strings.EqualFold(self, guestagent.WindowsPath) {
		return errors.New("trampoline requires the installed guest agent")
	}
	if err := guestagent.CheckRunnerContext(ctx); err != nil || !runnerDesktop() {
		return errors.New("runner context refused")
	}
	pin, err := guestagent.PinGuestDirectory()
	if err != nil {
		return errors.New("runner storage unavailable")
	}
	defer func() { _ = pin.Close() }()
	root, err := os.OpenRoot(guestBase)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return claimDetached(root, func(mode string) error {
		binary, childMode := guestagent.WindowsPath, "lab-probe"
		if mode == "listener" {
			helper, err := pin.OpenHelper()
			if err != nil {
				return errors.New("runner helper unavailable")
			}
			defer func() { _ = helper.Close() }()
			binary, childMode = filepath.Join(guestBase, "bivouac.exe"), "listener"
		}
		cmd := runnerChildCommand(binary, childMode)
		if mode == "lab-probe" {
			cmd.Env = append(os.Environ(), "BIVOUAC_LAB_SENTINEL=runner-task")
		}
		return cmd.Run()
	})
}
