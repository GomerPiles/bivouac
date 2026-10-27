//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

type anonymousFacts struct {
	Anonymous         bool   `json:"anonymous"`
	Connected         bool   `json:"connected"`
	Code              uint32 `json:"code,omitempty"`
	PrivateReadDenied bool   `json:"private_read_denied"`
	ManagerReadDenied bool   `json:"manager_read_denied"`
	TLSRefused        bool   `json:"tls_refused"`
}

// A separate diagnostic process uses an anonymous thread token, without
// creating accounts, changing groups or obtaining alternate credentials.
// This is not equivalent to launching a process under another primary user.
func anonymousProbe(ctx context.Context, runtimeID, recordPath string, out io.Writer) error {
	if windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("anonymous probe must be unelevated")
	}
	var record labRecord
	if readJSON(recordPath, &record) != nil || !record.valid() || record.Phase != "started" || record.Native == nil || record.Native.RuntimeID != runtimeID {
		return errors.New("recorded native route required")
	}
	host := labHost{record: record, output: filepath.Join(filepath.Dir(recordPath), "output")}
	startup, err := host.secureReport()
	if err != nil {
		return err
	}
	dial, err := nativeRaw(runtimeID)
	if err != nil {
		return err
	}
	parent := os.Getppid()
	if parent < 1 || uint64(parent) > uint64(^uint32(0)) {
		return errors.New("diagnostic parent unavailable")
	}
	parentID := uint32(parent)
	control, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, parentID)
	if err != nil {
		return errors.New("ordinary parent access control failed")
	}
	_ = windows.CloseHandle(control)
	// Positive reachability control also loads native socket support before
	// the thread changes identity. Never send commands on this connection.
	conn, err := dial(ctx)
	if err != nil {
		return errors.New("ordinary socket control failed")
	}
	_ = conn.Close()
	impersonate := windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateAnonymousToken")
	if impersonate.Find() != nil {
		return errors.New("anonymous token API unavailable")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	thread, err := windows.OpenThread(windows.THREAD_IMPERSONATE, false, windows.GetCurrentThreadId())
	if err != nil {
		return errors.New("anonymous thread unavailable")
	}
	defer func() { _ = windows.CloseHandle(thread) }()
	ok, _, _ := impersonate.Call(uintptr(thread))
	if ok == 0 {
		return errors.New("anonymous impersonation refused")
	}
	// A failed revert must terminate this disposable helper rather than let
	// an anonymous OS thread return to Go's thread pool.
	reverted := false
	defer func() {
		if !reverted && windows.RevertToSelf() != nil {
			os.Exit(1)
		}
	}()
	var token windows.Token
	if windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token) != nil {
		return errors.New("anonymous token verification unavailable")
	}
	user, tokenErr := token.GetTokenUser()
	_ = token.Close()
	if tokenErr != nil || !user.User.Sid.IsWellKnown(windows.WinAnonymousSid) {
		return errors.New("anonymous token identity refused")
	}
	facts := anonymousFacts{Anonymous: true}
	file, err := os.Open(recordPath)
	if file != nil {
		_ = file.Close()
	}
	facts.PrivateReadDenied = errors.Is(err, windows.ERROR_ACCESS_DENIED)
	process, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, parentID)
	if process != 0 {
		_ = windows.CloseHandle(process)
	}
	facts.ManagerReadDenied = errors.Is(err, windows.ERROR_ACCESS_DENIED)
	step, cancel := context.WithTimeout(ctx, 5*time.Second)
	conn, err = dial(step)
	if conn != nil {
		facts.Connected = true
		raw := conn
		secured, tlsErr := secureDial(tcpReport{Fingerprint: startup.Fingerprint}, tls.Certificate{}, func(context.Context) (net.Conn, error) { return raw, nil })(step)
		if secured != nil {
			_ = secured.SetDeadline(time.Now().Add(3 * time.Second))
			var value [1]byte
			_, tlsErr = secured.Read(value[:])
			_ = secured.Close()
		}
		var remote *net.OpError
		facts.TLSRefused = errors.As(tlsErr, &remote) && remote.Op == "remote error"
		_ = raw.Close()
	}
	cancel()
	if err != nil {
		var code windows.Errno
		if errors.As(err, &code) {
			facts.Code = uint32(code)
		}
	}
	if windows.RevertToSelf() != nil {
		//nolint:gocritic // Failed reversion must terminate without returning an impersonated OS thread to the pool.
		os.Exit(1)
	}
	reverted = true
	return json.NewEncoder(out).Encode(facts)
}
