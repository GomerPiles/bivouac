//go:build windows

package guestagent

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsCommand owns a private unnamed job and all stream/process handles.
// Commands inherit the agent's token, session, desktop and environment. All
// descendants remain in the job. Independent runner lifetimes belong to the
// separate on-demand runner task.
type windowsCommand struct {
	job, process windows.Handle
	jobOnce      sync.Once
	stop         func() bool
	callbackDone chan struct{}
	streams      []*os.File
	pumps        []*outputPump
	outputs      []io.Writer
}

type outputPump struct {
	done chan struct{}
	err  error // Published by closing done.
}

func (p *windowsCommand) closeJob() { p.jobOnce.Do(func() { _ = windows.CloseHandle(p.job) }) }
func (p *windowsCommand) Close() {
	if p.stop != nil && !p.stop() {
		<-p.callbackDone
	}
	p.closeJob()
	if p.process != 0 {
		p.abortOutput()
	}
	for _, f := range p.streams {
		_ = f.Close()
	}
	for _, pump := range p.pumps {
		<-pump.done
	}
	if p.process != 0 {
		_ = windows.CloseHandle(p.process)
	}
}

func (p *windowsCommand) abortOutput() {
	for _, writer := range p.outputs {
		if closer, ok := writer.(io.Closer); ok {
			_ = closer.Close()
		}
	}
}

func startCommand(ctx context.Context, req request, stdout, stderr io.Writer) (commandProcess, io.WriteCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// LookPath resolves an executable only. CreateProcess never invokes cmd.exe
	// or PowerShell, and batch scripts are refused rather than interpreted.
	binary, err := exec.LookPath(req.Argv[0])
	if err != nil {
		return nil, nil, err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, nil, err
	}
	if ext := strings.ToLower(filepath.Ext(binary)); ext == ".bat" || ext == ".cmd" {
		return nil, nil, errors.New("shell script refused")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	p := &windowsCommand{job: job, outputs: []io.Writer{stdout, stderr}}
	fail := func(err error) (commandProcess, io.WriteCloser, error) { p.Close(); return nil, nil, err }
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	// #nosec G103 -- Fixed job-limit structure used synchronously.
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return fail(err)
	}
	pipe := func() (*os.File, *os.File, error) {
		r, w, err := os.Pipe()
		if err == nil {
			p.streams = append(p.streams, r, w)
		}
		return r, w, err
	}
	outR, outW, err := pipe()
	if err != nil {
		return fail(err)
	}
	errR, errW, err := pipe()
	if err != nil {
		return fail(err)
	}
	var inR *os.File
	var stdin io.WriteCloser
	if req.Stdin {
		var inW *os.File
		inR, inW, err = pipe()
		stdin = inW
	} else {
		inR, err = os.Open(os.DevNull)
		if err == nil {
			p.streams = append(p.streams, inR)
		}
	}
	if err != nil {
		return fail(err)
	}
	handles := []windows.Handle{windows.Handle(inR.Fd()), windows.Handle(outW.Fd()), windows.Handle(errW.Fd())}
	for _, h := range handles {
		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return fail(err)
		}
	}
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return fail(err)
	}
	defer attrs.Delete()
	// #nosec G103 -- Only the three private standard streams are inherited.
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return fail(err)
	}
	const jobListAttribute = 0x0002000d
	jobs := []windows.Handle{job}
	// #nosec G103 -- Atomic assignment before the process can execute.
	if err := attrs.Update(jobListAttribute, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs[0])); err != nil {
		return fail(err)
	}
	startup := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{
		Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_HIDE, StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2],
	}, ProcThreadAttributeList: attrs.List()}
	application, err := windows.UTF16PtrFromString(binary)
	if err != nil {
		return fail(err)
	}
	// CRT-compatible escaping from the argument array, including empty strings,
	// quotes and trailing backslashes. No shell expansion or concatenated code.
	quoted := make([]string, len(req.Argv))
	for i, arg := range req.Argv {
		quoted[i] = windows.EscapeArg(arg)
	}
	command, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return fail(err)
	}
	var directory *uint16
	if home, err := os.UserHomeDir(); err == nil {
		directory, err = windows.UTF16PtrFromString(home)
		if err != nil {
			return fail(err)
		}
	}
	var process windows.ProcessInformation
	flags := uint32(windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT)
	// A nil environment and desktop inherit the agent's; no alternate token.
	if err := windows.CreateProcess(application, command, nil, nil, true, flags, nil, directory, &startup.StartupInfo, &process); err != nil {
		return fail(err)
	}
	p.process = process.Process
	_ = windows.CloseHandle(process.Thread)
	runtime.KeepAlive(handles)
	runtime.KeepAlive(jobs)
	_ = inR.Close()
	_ = outW.Close()
	_ = errW.Close()
	p.callbackDone = make(chan struct{})
	p.stop = context.AfterFunc(ctx, func() { p.closeJob(); p.abortOutput(); close(p.callbackDone) })
	for _, stream := range []struct {
		r *os.File
		w io.Writer
	}{{outR, stdout}, {errR, stderr}} {
		pump := &outputPump{done: make(chan struct{})}
		p.pumps = append(p.pumps, pump)
		go func() {
			_, pump.err = io.Copy(stream.w, stream.r)
			if pump.err != nil {
				p.closeJob()
			}
			close(pump.done)
		}()
	}
	return p, stdin, nil
}

func (p *windowsCommand) Wait() (int32, error) {
	state, err := windows.WaitForSingleObject(p.process, windows.INFINITE)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		return 0, errors.New("command wait failed")
	}
	var code uint32
	if err := windows.GetExitCodeProcess(p.process, &code); err != nil {
		return 0, errors.New("command status unavailable")
	}
	// Normal exit ends all descendants too.
	p.closeJob()
	timer := time.NewTimer(outputDelay)
	defer timer.Stop()
	for _, pump := range p.pumps {
		select {
		case <-pump.done:
			if pump.err != nil {
				return 0, exec.ErrWaitDelay
			}
		case <-timer.C:
			p.abortOutput()
			return 0, exec.ErrWaitDelay
		}
	}
	return int32(code), nil //nolint:gosec // Preserve the full Windows exit-code bit pattern.
}
