//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/GomerPiles/bivouac/internal/winhost"
	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// The experiment is session-only: one explicit elevation, two successful
// metadata queries, a five-minute deadline, no installation or host mutation.
const brokerClientAccess = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE | windows.READ_CONTROL

type brokerRequest struct {
	Protocol int    `json:"protocol"`
	Op       string `json:"op"`
	Nonce    string `json:"nonce"`
}

type brokerResponse struct {
	Protocol   int             `json:"protocol"`
	Nonce      string          `json:"nonce"`
	Code       string          `json:"code"`
	Candidates []nativeBinding `json:"candidates,omitempty"`
}

func brokerPipe(id string) (string, error) {
	if !validGUID(id) {
		return "", errors.New("broker session UUID required")
	}
	return `\\.\pipe\bivouac-sandbox-discovery-lab-` + id, nil
}

func brokerDescriptor(account string) (string, error) {
	sid, err := windows.StringToSid(account)
	if err != nil || sid.String() != account || !sid.IsValid() {
		return "", errors.New("broker account SID required")
	}
	// FILE_CREATE_PIPE_INSTANCE is deliberately absent from the client mask.
	return fmt.Sprintf("O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x%x;;;%s)", brokerClientAccess, account), nil
}

func writeBrokerFrame(out io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) < 1 || len(data) > 65536 {
		return errors.New("broker frame refused")
	}
	if err := binary.Write(out, binary.BigEndian, uint32(len(data))); err != nil { // #nosec G115 -- Payload length is checked above against 65536.
		return errors.New("broker frame header unavailable")
	}
	_, err = io.Copy(out, bytes.NewReader(data))
	return err
}

func readBrokerFrame(in io.Reader, max uint32, value any) error {
	var size uint32
	if binary.Read(in, binary.BigEndian, &size) != nil || size < 1 || size > max {
		return errors.New("broker frame size refused")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(in, data); err != nil {
		return errors.New("broker frame truncated")
	}
	return decodeBounded(bytes.NewReader(data), value)
}

func brokerOwner(conn net.Conn) error {
	file, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("broker endpoint is not a pipe")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("broker pipe owner unavailable")
	}
	owner, _, err := sd.Owner()
	if err != nil || (!owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid)) {
		return errors.New("broker pipe lacks privileged owner")
	}
	return nil
}

func brokerCaller(conn net.Conn) (string, error) {
	file, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return "", errors.New("broker caller is not a pipe")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	impersonate := windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
	if ok, _, _ := impersonate.Call(file.Fd()); ok == 0 {
		return "", errors.New("broker caller identification unavailable")
	}
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if windows.RevertToSelf() != nil {
		//nolint:gocritic // A failed revert must terminate rather than return an impersonated OS thread to the pool.
		os.Exit(1)
	}
	if err != nil {
		return "", errors.New("broker caller token unavailable")
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", errors.New("broker caller SID unavailable")
	}
	return user.User.Sid.String(), nil
}

type metadataBroker struct {
	account  string
	identify func(net.Conn) (string, error)
	query    func(context.Context, io.Writer) error
	seen     map[string]bool
}

func (b *metadataBroker) handle(ctx context.Context, conn net.Conn) bool {
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var request brokerRequest
	if readBrokerFrame(conn, 1024, &request) != nil {
		return false
	}
	response := brokerResponse{Protocol: 1, Nonce: request.Nonce, Code: "refused"}
	// Read before impersonation; revert before any privileged HCS query.
	account, err := b.identify(conn)
	if err == nil && account == b.account && request.Protocol == 1 && request.Op == "candidates" && validGUID(request.Nonce) && !b.seen[request.Nonce] && len(b.seen) < 32 {
		b.seen[request.Nonce] = true
		step, cancel := context.WithTimeout(ctx, 5*time.Second)
		var output boundedBuffer
		err := b.query(step, &output)
		cancel()
		var candidates []nativeBinding
		if err == nil && decodeBounded(bytes.NewReader(output.data), &candidates) == nil && len(candidates) <= 16 {
			response.Code = "ok"
			response.Candidates = candidates
		} else {
			response.Code = "unavailable"
		}
	}
	return writeBrokerFrame(conn, response) == nil && response.Code == "ok"
}

func serveBroker(ctx context.Context, id, account string) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("metadata broker requires explicit elevation")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid.String() != account {
		return errors.New("lab broker must remain within its elevating account")
	}
	name, err := brokerPipe(id)
	if err != nil {
		return err
	}
	descriptor, err := brokerDescriptor(account)
	if err != nil {
		return err
	}
	listener, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: descriptor})
	if err != nil {
		return errors.New("fresh broker endpoint required")
	}
	defer func() { _ = listener.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	broker := metadataBroker{account: account, identify: brokerCaller, query: nativeCandidates, seen: map[string]bool{}}
	for queries := 0; queries < 2; {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("broker accept unavailable")
		}
		if broker.handle(ctx, conn) {
			queries++
		}
	}
	return nil
}

func dialBroker(ctx context.Context, id string) (net.Conn, error) {
	name, err := brokerPipe(id)
	if err != nil {
		return nil, err
	}
	conn, err := winio.DialPipeAccessImpLevel(ctx, name, brokerClientAccess, winio.PipeImpLevelIdentification)
	if err != nil {
		return nil, errors.New("metadata broker unavailable")
	}
	if err := brokerOwner(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func brokerCandidates(ctx context.Context, id string) ([]nativeBinding, error) {
	step, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	conn, err := dialBroker(step, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(step, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	nonce, err := newID()
	if err != nil {
		return nil, err
	}
	if writeBrokerFrame(conn, brokerRequest{Protocol: 1, Op: "candidates", Nonce: nonce}) != nil {
		return nil, errors.New("broker request unavailable")
	}
	var response brokerResponse
	if readBrokerFrame(conn, 65536, &response) != nil || response.Protocol != 1 || response.Nonce != nonce || response.Code != "ok" || len(response.Candidates) > 16 {
		return nil, errors.New("broker metadata refused")
	}
	return response.Candidates, nil
}

func startBrokerSession(ctx context.Context, base string, out io.Writer) error {
	if windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("broker session launcher must remain unelevated")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return errors.New("broker account unavailable")
	}
	id, err := newID()
	if err != nil {
		return err
	}
	base, err = filepath.Abs(base)
	if err != nil {
		return errors.New("broker lab directory unavailable")
	}
	self, err := os.Executable()
	if err != nil {
		return errors.New("broker executable unavailable")
	}
	// Fresh per-session copy is authorized by this UAC prompt only. A future
	// persistent service must instead use an administrator-protected install.
	dir, err := winhost.PrivateDirectory(base)
	if err != nil {
		return errors.New("fresh broker directory unavailable")
	}
	helper := filepath.Join(dir, "sandbox-lab.exe")
	if copyAsset(self, helper, 512<<20) != nil {
		return errors.New("broker executable copy failed")
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(helper)
	args, _ := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{"broker", id, user.User.Sid.String()}))
	cwd, _ := windows.UTF16PtrFromString(dir)
	if windows.ShellExecute(0, verb, file, args, cwd, windows.SW_HIDE) != nil {
		return errors.New("broker session elevation unavailable")
	}
	wait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		attempt, cancel := context.WithTimeout(wait, time.Second)
		conn, err := dialBroker(attempt, id)
		cancel()
		if err == nil {
			_ = conn.Close()
			break
		}
		if pause(wait) != nil {
			return errors.New("broker session readiness unavailable")
		}
	}
	return json.NewEncoder(out).Encode(struct {
		Session         string `json:"session"`
		Queries         int    `json:"queries"`
		LifetimeSeconds int    `json:"lifetime_seconds"`
	}{id, 2, 300})
}

func brokerAccountCheck(ctx context.Context, id string, out io.Writer) error {
	if windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("broker account check must remain unelevated")
	}
	if _, err := brokerCandidates(ctx, id); err != nil {
		return errors.New("ordinary broker query control failed")
	}
	name, err := brokerPipe(id)
	if err != nil {
		return err
	}
	denied, err := anonymousBrokerDial(ctx, name)
	if err != nil || !denied {
		return errors.New("anonymous broker access denial unproven")
	}
	if _, err := brokerCandidates(ctx, id); err != nil {
		return errors.New("ordinary broker query after refusal failed")
	}
	return json.NewEncoder(out).Encode(struct {
		AnonymousDenied bool `json:"anonymous_denied"`
		QueryBefore     bool `json:"query_before"`
		QueryAfter      bool `json:"query_after"`
	}{true, true, true})
}

func anonymousBrokerDial(ctx context.Context, name string) (bool, error) {
	impersonate := windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateAnonymousToken")
	if impersonate.Find() != nil {
		return false, errors.New("anonymous API unavailable")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	thread, err := windows.OpenThread(windows.THREAD_IMPERSONATE, false, windows.GetCurrentThreadId())
	if err != nil {
		return false, errors.New("anonymous thread unavailable")
	}
	defer func() { _ = windows.CloseHandle(thread) }()
	if ok, _, _ := impersonate.Call(uintptr(thread)); ok == 0 {
		return false, errors.New("anonymous impersonation unavailable")
	}
	defer func() {
		if windows.RevertToSelf() != nil {
			os.Exit(1)
		}
	}()
	var token windows.Token
	if windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token) != nil {
		return false, errors.New("anonymous identity unavailable")
	}
	user, err := token.GetTokenUser()
	_ = token.Close()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinAnonymousSid) {
		return false, errors.New("anonymous identity differs")
	}
	step, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := winio.DialPipeAccessImpLevel(step, name, brokerClientAccess, winio.PipeImpLevelIdentification)
	if conn != nil {
		_ = conn.Close()
	}
	return errors.Is(err, windows.ERROR_ACCESS_DENIED), nil
}
