//go:build windows

package guestagent

import (
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessInJob checks all enclosing jobs, including a Task Scheduler job.
func ProcessInJob(process windows.Handle) (bool, error) {
	var inside int32
	// #nosec G103 -- IsProcessInJob writes one BOOL synchronously.
	ok, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(uintptr(process), 0, uintptr(unsafe.Pointer(&inside)))
	if ok == 0 {
		return false, err
	}
	return inside != 0, nil
}

// CheckBreakaway proves explicit breakaway creation using a suspended copy of
// this executable, so no child code runs, then terminates and joins it.
// Actual Task Scheduler/agent lifetime independence is a separate live gate.
// No runner input or launch marker has been consumed when this probe fails.
func CheckBreakaway() error {
	self, err := os.Executable()
	if err != nil {
		return errors.New("breakaway unavailable")
	}
	application, err := windows.UTF16PtrFromString(self)
	if err != nil {
		return errors.New("breakaway unavailable")
	}
	argv := []string{self, "version"}
	for i, arg := range argv {
		argv[i] = windows.EscapeArg(arg)
	}
	command, err := windows.UTF16PtrFromString(strings.Join(argv, " "))
	if err != nil {
		return errors.New("breakaway unavailable")
	}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var p windows.ProcessInformation
	if windows.CreateProcess(application, command, nil, nil, false, windows.CREATE_SUSPENDED|windows.CREATE_BREAKAWAY_FROM_JOB|windows.CREATE_NO_WINDOW, nil, nil, &startup, &p) != nil {
		return errors.New("breakaway unavailable")
	}
	defer func() { _ = windows.CloseHandle(p.Thread); _ = windows.CloseHandle(p.Process) }()
	terminateErr := windows.TerminateProcess(p.Process, 0)
	state, waitErr := windows.WaitForSingleObject(p.Process, 5000)
	if terminateErr != nil || waitErr != nil || state != windows.WAIT_OBJECT_0 {
		return errors.New("breakaway unavailable")
	}
	return nil
}
