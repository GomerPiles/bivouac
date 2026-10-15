//go:build windows

package crosvm

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func hideSupervisor(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW}
}

// startSupervisor leaves any job object around the controller, so closing a
// kill-on-close job there cannot kill VMs meant for adoption. A job that
// forbids breakaway makes CreateProcess fail with ERROR_ACCESS_DENIED before
// any process exists; the supervisor then starts inside that job instead and
// detached reports false. Standard streams are the null device: no pipe or
// copying goroutine outlives the released handle.
func startSupervisor(name string, args ...string) (process *os.Process, detached bool, err error) {
	start := func(flags uint32) (*os.Process, error) {
		cmd := exec.Command(name, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: flags}
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return cmd.Process, nil
	}
	flags := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW)
	process, err = start(flags | windows.CREATE_BREAKAWAY_FROM_JOB)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		process, err = start(flags)
		return process, false, err
	}
	return process, err == nil, err
}

type ProcessIdentity struct {
	PID     uint32 `json:"pid"`
	Created uint64 `json:"created"`
	Image   string `json:"image"`
}
type nativeChild struct {
	job      windows.Handle
	process  windows.Handle
	identity ProcessIdentity
	streams  []*os.File
	pumps    []chan error
}

func jobName(r Record) string {
	return `Local\bivouac-crosvm-` + r.Meta.ControllerID + "-" + r.Meta.InstanceID
}

func Identity(pid uint32) (ProcessIdentity, bool, error) {
	if pid == 0 {
		return ProcessIdentity{}, false, errors.New("invalid native PID")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return ProcessIdentity{}, false, nil
	}
	if err != nil {
		// During forced job teardown Windows can deny OpenProcess for an exited
		// PID. Accept absence only with an independent native process snapshot;
		// an inaccessible live/reused PID remains an error.
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			_, present, snapshotErr := processSnapshot(pid)
			if snapshotErr == nil && !present {
				return ProcessIdentity{}, false, nil
			}
		}
		return ProcessIdentity{}, false, err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	state, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return ProcessIdentity{}, false, err
	}
	if state == windows.WAIT_OBJECT_0 {
		return ProcessIdentity{}, false, nil
	}
	if state != uint32(windows.WAIT_TIMEOUT) {
		return ProcessIdentity{}, false, errors.New("unexpected native process wait state")
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return ProcessIdentity{}, false, err
	}
	image, err := processImage(handle)
	if err != nil {
		return ProcessIdentity{}, false, err
	}
	return ProcessIdentity{PID: pid, Created: uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), Image: image}, true, nil
}

// processImage names a process's executable by its final path, as Canonical
// names the configured binary. QueryFullProcessImageName keeps the spelling
// the image was opened with, including 8.3 short names, so it is resolved
// again; an image that can no longer be opened keeps the reported path.
func processImage(handle windows.Handle) (string, error) {
	var image [32768]uint16
	length := uint32(len(image))
	if err := windows.QueryFullProcessImageName(handle, 0, &image[0], &length); err != nil {
		return "", err
	}
	path := windows.UTF16ToString(image[:length])
	if resolved, err := resolvePath(path); err == nil {
		return resolved, nil
	}
	return path, nil
}

// processSnapshot reports whether pid is present and its executable base name.
func processSnapshot(pid uint32) (string, bool, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if entry.ProcessID == pid {
			return windows.UTF16ToString(entry.ExeFile[:]), true, nil
		}
	}
	if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return "", false, nil
	}
	return "", false, err
}

// sameProcess reports whether the recorded process is still alive. A PID now
// owned by a process with another creation time or executable name proves the
// recorded process exited: Windows reuses PIDs, notably after a reboot. Only
// the same PID and creation time with a different image is contradictory.
func sameProcess(expected ProcessIdentity) (bool, error) {
	actual, live, err := Identity(expected.PID)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		// A reused PID can belong to a process this user cannot open. Our own
		// supervisor and VM are always openable unless exiting, so a different
		// executable name in the snapshot proves the recorded process is gone.
		name, present, snapshotErr := processSnapshot(expected.PID)
		if snapshotErr == nil && (!present || !strings.EqualFold(name, imageBase(expected.Image))) {
			return false, nil
		}
		return false, err
	}
	if err != nil || !live {
		return live, err
	}
	return compareIdentity(expected, actual)
}
func startNative(o Options, r Record, output, errorsOutput io.Writer, journal func() error) (*nativeChild, error) {
	args, env, err := Launch(o, r)
	if err != nil {
		return nil, err
	}
	return startJob(o.Binary, args, env, jobName(r), output, errorsOutput, journal)
}

func startJob(binary string, args, env []string, name string, output, errorsOutput io.Writer, journal func() error) (*nativeChild, error) {
	jobText, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	create := windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateJobObjectW")
	// The x/sys wrapper discards LastError on success; named creation must also
	// distinguish a fresh job from ERROR_ALREADY_EXISTS before changing limits.
	// #nosec G103 -- Documented synchronous UTF-16 name argument.
	h, _, callErr := create.Call(0, uintptr(unsafe.Pointer(jobText)))
	if h == 0 {
		return nil, callErr
	}
	job := windows.Handle(h)
	if errors.Is(callErr, windows.ERROR_ALREADY_EXISTS) {
		_ = windows.CloseHandle(job)
		return nil, errors.New("native job already exists; refusing to adopt it")
	}
	child := &nativeChild{job: job}
	fail := func(err error) (*nativeChild, error) { _ = child.Close(); return nil, err }
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	// #nosec G103 -- Fixed documented job-limit structure passed synchronously to the Windows API.
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return fail(err)
	}
	// Persist ownership before any process is created. A failed journal closes
	// this empty job, and never permits a child launch.
	if err := journal(); err != nil {
		return fail(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		return fail(err)
	}
	child.streams = append(child.streams, outR, outW)
	errR, errW, err := os.Pipe()
	if err != nil {
		return fail(err)
	}
	child.streams = append(child.streams, errR, errW)
	null, err := os.Open("NUL")
	if err != nil {
		return fail(err)
	}
	child.streams = append(child.streams, null)
	handles := []windows.Handle{windows.Handle(outW.Fd()), windows.Handle(errW.Fd()), windows.Handle(null.Fd())}
	for _, handle := range handles {
		if err := windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return fail(err)
		}
	}
	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return fail(err)
	}
	defer attributes.Delete()
	// #nosec G103 -- Only these three private standard-stream handles may be inherited.
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return fail(err)
	}
	// PROC_THREAD_ATTRIBUTE_JOB_LIST assigns the job atomically during creation,
	// closing the supervisor-crash gap between CreateProcess and AssignProcess.
	const jobListAttribute = 0x0002000d
	jobs := []windows.Handle{job}
	// #nosec G103 -- Documented one-element native job list, retained through creation.
	if err := attributes.Update(jobListAttribute, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs[0])); err != nil {
		return fail(err)
	}
	startup := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES, StdOutput: handles[0], StdErr: handles[1], StdInput: handles[2]}, ProcThreadAttributeList: attributes.List()}
	application, err := windows.UTF16PtrFromString(binary)
	if err != nil {
		return fail(err)
	}
	quoted := []string{windows.EscapeArg(binary)}
	for _, arg := range args {
		quoted = append(quoted, windows.EscapeArg(arg))
	}
	command, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return fail(err)
	}
	environment := []string{}
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		upper := strings.ToUpper(key)
		if upper != "CROSVM_SLIRP_SSH_PORT" && upper != "BIVOUAC_SLIRP_POLICY" && upper != "BIVOUAC_SLIRP_HOST_PREFIXES" {
			environment = append(environment, value)
		}
	}
	environment = append(environment, env...)
	// Windows consumes a double-NUL terminated Unicode environment block.
	sort.Slice(environment, func(i, j int) bool { return strings.ToUpper(environment[i]) < strings.ToUpper(environment[j]) })
	var block []uint16
	for _, value := range environment {
		entry, encodeErr := windows.UTF16FromString(value)
		if encodeErr != nil {
			return fail(encodeErr)
		}
		block = append(block, entry...)
	}
	block = append(block, 0)
	directory, err := windows.UTF16PtrFromString(filepath.Dir(binary))
	if err != nil {
		return fail(err)
	}
	var process windows.ProcessInformation
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := windows.CreateProcess(application, command, nil, nil, true, flags, &block[0], directory, &startup.StartupInfo, &process); err != nil {
		return fail(err)
	}
	child.process = process.Process
	defer func() { _ = windows.CloseHandle(process.Thread) }()
	identity, live, err := Identity(process.ProcessId)
	if err != nil || !live {
		_ = windows.TerminateJobObject(job, 1)
		return fail(errors.New("created native process identity unavailable"))
	}
	child.identity = identity
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		return fail(err)
	}
	runtime.KeepAlive(handles)
	runtime.KeepAlive(jobs)
	runtime.KeepAlive(block)
	_ = outW.Close()
	_ = errW.Close()
	_ = null.Close()
	for _, stream := range []struct {
		r *os.File
		w io.Writer
	}{{outR, output}, {errR, errorsOutput}} {
		done := make(chan error, 1)
		child.pumps = append(child.pumps, done)
		go func() { _, err := io.Copy(stream.w, stream.r); done <- err }()
	}
	return child, nil
}

// recoverJob is called only after the recorded supervisor is confirmed absent
// and its journal proves that it created this job. The handle is short-lived:
// recovery terminates remaining children and confirms native accounting is empty.
func recoverJob(ctx context.Context, r Record) error {
	name, err := windows.UTF16PtrFromString(jobName(r))
	if err != nil {
		return err
	}
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("OpenJobObjectW")
	const queryAndTerminate = 0x0004 | 0x0008
	// #nosec G103 -- Synchronous documented UTF-16 argument to OpenJobObjectW.
	h, _, callErr := proc.Call(queryAndTerminate, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		if errors.Is(callErr, windows.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		return callErr
	}
	job := windows.Handle(h)
	defer func() { _ = windows.CloseHandle(job) }()
	if err := windows.TerminateJobObject(job, 1); err != nil {
		return err
	}
	return (&nativeChild{job: job}).WaitEmpty(ctx)
}
func (p *nativeChild) Alive() (bool, error) {
	state, err := windows.WaitForSingleObject(p.process, 0)
	if err != nil {
		return false, err
	}
	return state == uint32(windows.WAIT_TIMEOUT), nil
}

func diskCapacity(path string) (uint64, error) {
	text, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var available uint64
	err = windows.GetDiskFreeSpaceEx(text, &available, nil, nil)
	return available, err
}

// terminateRecorded is used only by the explicit credential-free crash test.
// Verification and termination use the same native handle, avoiding PID reuse.
func terminateRecorded(expected ProcessIdentity) error {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, expected.PID)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return err
	}
	image, err := processImage(h)
	if err != nil {
		return err
	}
	if uint64(created.HighDateTime)<<32|uint64(created.LowDateTime) != expected.Created || !sameImage(image, expected.Image) {
		return errors.New("refusing to terminate changed native process identity")
	}
	return windows.TerminateProcess(h, 1)
}
func (p *nativeChild) Stop() error { return windows.TerminateJobObject(p.job, 1) }
func (p *nativeChild) Empty() (bool, error) {
	var accounting struct {
		User, Kernel, PeriodUser, PeriodKernel int64
		Faults, Processes, Active, Terminated  uint32
	}
	// #nosec G103 -- Fixed JOBOBJECT_BASIC_ACCOUNTING_INFORMATION output structure.
	err := windows.QueryInformationJobObject(p.job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil)
	return accounting.Active == 0, err
}
func (p *nativeChild) WaitEmpty(ctx context.Context) error {
	for {
		empty, err := p.Empty()
		if err != nil {
			return err
		}
		if empty {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (p *nativeChild) Close() error {
	var failures []error
	if p.job != 0 {
		failures = append(failures, windows.CloseHandle(p.job))
		p.job = 0
	}
	if p.process != 0 {
		failures = append(failures, windows.CloseHandle(p.process))
		p.process = 0
	}
	for _, stream := range p.streams {
		_ = stream.Close()
	}
	return errors.Join(failures...)
}
