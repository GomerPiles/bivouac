//go:build windows

package imagefactory

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type workerPIDWriter struct {
	buffer bytes.Buffer
	cancel context.CancelFunc
	handle windows.Handle
}

func (w *workerPIDWriter) Write(b []byte) (int, error) {
	n, e := w.buffer.Write(b)
	if bytes.Contains(w.buffer.Bytes(), []byte{'\n'}) && w.handle == 0 {
		pid, err := strconv.ParseUint(strings.TrimSpace(w.buffer.String()), 10, 32)
		if err != nil {
			return n, err
		}
		w.handle, err = windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
		if err != nil {
			return n, err
		}
		w.cancel()
	}
	return n, e
}
func TestHostWorkerCancellationJoinsDescendants(t *testing.T) {
	system, e := windows.GetSystemDirectory()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	out := &workerPIDWriter{cancel: cancel}
	child := encodedPowerShell(`Start-Sleep -Seconds 60`)
	script := `$p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','` + child + `') -WindowStyle Hidden -PassThru;[Console]::Out.WriteLine($p.Id);[Console]::Out.Flush();Start-Sleep -Seconds 60`
	_, e = runHostProcess(ctx, []string{filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedPowerShell(script)}, hostPowerShellEnvironment(system), nil, out, "")
	if out.handle == 0 {
		t.Fatal("descendant identity unavailable")
	}
	defer func() { _ = windows.CloseHandle(out.handle) }()
	state, waitErr := windows.WaitForSingleObject(out.handle, 0)
	if e == nil || waitErr != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatal("host worker descendant survived cancellation")
	}
}
func TestHostWorkerRefusesExistingJob(t *testing.T) {
	name := `Local\bivouac-image-test-` + hashBytes([]byte(t.TempDir()))[:32]
	utf, e := windows.UTF16PtrFromString(name)
	if e != nil {
		t.Fatal(e)
	}
	job, e := windows.CreateJobObject(nil, utf)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = windows.CloseHandle(job) }()
	_, e = runHostProcess(t.Context(), []string{"must-not-execute"}, nil, nil, io.Discard, name)
	if e == nil || !strings.Contains(e.Error(), "previous image host worker") {
		t.Fatal("cleanup could overtake earlier worker")
	}
}
