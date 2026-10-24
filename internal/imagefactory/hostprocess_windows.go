//go:build windows

package imagefactory

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Every host helper and its DISM/BCDEdit descendants are atomically born in a
// private kill-on-close job. The creating process owns the only job handle;
// cancellation and factory death cannot leave an apply running independently.
// A deterministic name prevents cleanup overtaking an older job's termination.
func runHostProcess(ctx context.Context, argv, env []string, input []byte, output io.Writer, jobName string) (uint32, error) {
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	var name *uint16
	var err error
	if jobName != "" {
		name, err = windows.UTF16PtrFromString(jobName)
		if err != nil {
			return 0, err
		}
	}
	sddl, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return 0, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sddl}
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateJobObjectW")
	h, _, callErr := proc.Call(uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(name))) // #nosec G103 -- synchronous fixed security descriptor and optional UTF-16 name.
	if h == 0 {
		return 0, errors.New("cannot create image host worker job")
	}
	job := windows.Handle(h)
	defer func() { _ = windows.CloseHandle(job) }()
	if errors.Is(callErr, windows.ERROR_ALREADY_EXISTS) {
		return 0, errors.New("previous image host worker still exists; workspace retained")
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return 0, errors.New("cannot confine image host worker")
	} // #nosec G103 -- fixed Windows job ABI.
	var files []*os.File
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	pipe := func() (*os.File, *os.File, error) {
		r, w, e := os.Pipe()
		if e == nil {
			files = append(files, r, w)
		}
		return r, w, e
	}
	inR, inW, err := pipe()
	if err != nil {
		return 0, err
	}
	outR, outW, err := pipe()
	if err != nil {
		return 0, err
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return 0, err
	}
	files = append(files, null)
	handles := []windows.Handle{windows.Handle(inR.Fd()), windows.Handle(outW.Fd()), windows.Handle(null.Fd())}
	for _, handle := range handles {
		if err = windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return 0, err
		}
	}
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return 0, err
	}
	defer attrs.Delete()
	if err = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return 0, err
	} // #nosec G103 -- private inherited standard handles only.
	jobs := []windows.Handle{job}
	if err = attrs.Update(0x0002000d, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs[0])); err != nil {
		return 0, err
	} // #nosec G103 -- PROC_THREAD_ATTRIBUTE_JOB_LIST provides atomic confinement.
	startup := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES, StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2]}, ProcThreadAttributeList: attrs.List()}
	application, err := windows.UTF16PtrFromString(argv[0])
	if err != nil {
		return 0, err
	}
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		quoted[i] = windows.EscapeArg(arg)
	}
	command, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return 0, err
	}
	sort.Slice(env, func(i, j int) bool { return strings.ToUpper(env[i]) < strings.ToUpper(env[j]) })
	var block []uint16
	for _, entry := range env {
		words, e := windows.UTF16FromString(entry)
		if e != nil {
			return 0, e
		}
		block = append(block, words...)
	}
	block = append(block, 0)
	var p windows.ProcessInformation
	flags := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err = windows.CreateProcess(application, command, nil, nil, true, flags, &block[0], nil, &startup.StartupInfo, &p); err != nil {
		return 0, errors.New("image host worker launch failed")
	}
	defer func() { _ = windows.CloseHandle(p.Process) }()
	_ = windows.CloseHandle(p.Thread)
	runtime.KeepAlive(handles)
	runtime.KeepAlive(jobs)
	runtime.KeepAlive(block)
	_ = inR.Close()
	_ = outW.Close()
	var terminate sync.Once
	stop := func() { terminate.Do(func() { _ = windows.TerminateJobObject(job, 1) }) }
	callbackDone := make(chan struct{})
	cancel := context.AfterFunc(ctx, func() { stop(); _ = inW.Close(); close(callbackDone) })
	defer func() {
		if !cancel() {
			<-callbackDone
		}
	}()
	writeDone := make(chan error, 1)
	go func() { _, e := inW.Write(input); _ = inW.Close(); writeDone <- e }()
	readDone := make(chan error, 1)
	go func() {
		_, e := io.Copy(output, outR)
		if e != nil {
			stop()
		}
		readDone <- e
	}()
	state, waitErr := windows.WaitForSingleObject(p.Process, windows.INFINITE)
	stop() // A successful helper also cannot leave background descendants.
	var code uint32
	statusErr := windows.GetExitCodeProcess(p.Process, &code)
	// Wait for all owned processes to exit before allowing storage cleanup.
	deadline := time.Now().Add(30 * time.Second)
	for {
		var accounting struct {
			User, Kernel, PeriodUser, PeriodKernel int64
			Faults, Processes, Active, Terminated  uint32
		}
		e := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil) // #nosec G103 -- fixed job accounting ABI.
		if e != nil || time.Now().After(deadline) {
			_ = outR.Close()
			_ = inW.Close()
			<-readDone
			<-writeDone
			return 0, errors.New("image host worker absence unconfirmed")
		}
		if accounting.Active == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	readErr, writeErr := <-readDone, <-writeDone
	if waitErr != nil || state != windows.WAIT_OBJECT_0 || statusErr != nil || readErr != nil || (writeErr != nil && code == 0) || ctx.Err() != nil {
		return code, errors.New("image host worker failed")
	}
	return code, nil
}
