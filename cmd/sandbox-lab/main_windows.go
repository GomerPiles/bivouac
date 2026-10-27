//go:build windows

// sandbox-lab is an opt-in Windows Sandbox experiment. It never loads a
// controller configuration, calls GitHub, or mutates the HCS VM host.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/hcs"
	"github.com/GomerPiles/bivouac/internal/hvsock"
	"github.com/GomerPiles/bivouac/internal/redact"
	winio "github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"golang.org/x/sys/windows"
)

const serviceID = "d9b727ec-24a5-4546-9e99-e7f21834808e"
const guestBinary = `C:\Program Files\Bivouac\sandbox-lab.exe`
const reportDirectory = `C:\BivouacReport`

type sessionFacts struct {
	Session  uint32 `json:"session"`
	Console  uint32 `json:"console"`
	User     bool   `json:"user"`
	Elevated bool   `json:"elevated"`
	Active   bool   `json:"active"`
	Desktop  bool   `json:"desktop"`
}

func (f sessionFacts) valid() bool {
	return f.Session != 0 && f.User && f.Elevated && f.Active && f.Desktop
}

func session() sessionFacts {
	var f sessionFacts
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &f.Session) != nil {
		return f
	}
	f.Console = windows.WTSGetActiveConsoleSessionId()
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return f
	}
	expected, _, kind, err := windows.LookupSID("", "WDAGUtilityAccount")
	f.User = err == nil && kind == windows.SidTypeUser && user.User.Sid.Equals(expected)
	f.Elevated = token.IsElevated()
	dll := windows.NewLazySystemDLL("wtsapi32.dll")
	var buffer *byte
	var size uint32
	// #nosec G103 -- WTS allocates this bounded connection-state result.
	ok, _, _ := dll.NewProc("WTSQuerySessionInformationW").Call(0, uintptr(f.Session), 8, uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&size)))
	if buffer != nil {
		// #nosec G103 -- Free only the allocation returned by WTS above.
		defer func() { _, _, _ = dll.NewProc("WTSFreeMemory").Call(uintptr(unsafe.Pointer(buffer))) }()
		if ok != 0 && size == 4 {
			// #nosec G103 -- WTS returned exactly one DWORD.
			f.Active = *(*uint32)(unsafe.Pointer(buffer)) == 0
		} // WTSActive
	}
	ui := windows.NewLazySystemDLL("user32.dll")
	station, _, _ := ui.NewProc("GetProcessWindowStation").Call()
	desktop, _, _ := ui.NewProc("GetThreadDesktop").Call(uintptr(windows.GetCurrentThreadId()))
	name := func(handle uintptr) string {
		var text [256]uint16
		var needed uint32
		// #nosec G103 -- Fixed UOI_NAME output and borrowed UI handles.
		ok, _, _ := ui.NewProc("GetUserObjectInformationW").Call(handle, 2, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)*2), uintptr(unsafe.Pointer(&needed)))
		if ok == 0 || needed > uint32(len(text)*2) {
			return ""
		}
		return windows.UTF16ToString(text[:])
	}
	f.Desktop = name(station) == "WinSta0" && name(desktop) == "Default"
	return f
}

type parentListener struct{ net.Listener }

func (l parentListener) Accept() (io.ReadWriteCloser, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if !session().valid() {
		_ = conn.Close()
		return nil, errors.New("sandbox session refused")
	}
	return conn, nil
}

func agent(ctx context.Context) error {
	self, err := os.Executable()
	if err != nil || !strings.EqualFold(self, guestBinary) {
		return errors.New("sandbox agent installation refused")
	}
	f := session()
	if err := writeReport("agent.json", f); err != nil {
		return err
	}
	if !f.valid() {
		return errors.New("sandbox session refused")
	}
	service, err := guid.FromString(serviceID)
	if err != nil {
		return errors.New("sandbox service invalid")
	}
	l, err := winio.ListenHvsock(&winio.HvsockAddr{VMID: winio.HvsockGUIDParent(), ServiceID: service})
	if err != nil {
		return errors.New("sandbox listener unavailable")
	}
	defer func() { _ = l.Close() }()
	return guestagent.Serve(ctx, parentListener{l})
}

func writeReport(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return errors.New("encode report")
	}
	return os.WriteFile(filepath.Join(reportDirectory, name), data, 0o600)
}

func inspect(ctx context.Context, id string) error {
	if _, err := hvsock.ParseGUID(id); err != nil {
		return errors.New("invalid Sandbox ID")
	}
	facts := struct {
		HCS       bool         `json:"hcs"`
		Running   bool         `json:"running"`
		IDMatches bool         `json:"id_matches"`
		VM        bool         `json:"vm"`
		Runtime   bool         `json:"runtime"`
		Agent     bool         `json:"agent"`
		OpenCode  uint32       `json:"open_code,omitempty"`
		DialCode  uint32       `json:"dial_code,omitempty"`
		Session   sessionFacts `json:"guest_session"`
	}{}
	a, err := hcs.Load()
	if err != nil {
		return errors.New("native inspection unavailable")
	}
	s, err := a.Open(ctx, id)
	if err != nil {
		var native *hcs.Error
		if errors.As(err, &native) {
			facts.OpenCode = native.Code
		}
		return json.NewEncoder(os.Stdout).Encode(facts)
	}
	defer s.Close()
	p, err := s.Properties(ctx)
	if err != nil {
		return errors.New("native properties unavailable")
	}
	facts.HCS, facts.Running, facts.IDMatches, facts.VM = true, p.State == hcs.StateRunning, strings.EqualFold(p.ID, id), p.SystemType == hcs.SystemTypeVM
	vm, err := hvsock.ParseGUID(p.RuntimeID)
	if err != nil {
		return json.NewEncoder(os.Stdout).Encode(facts)
	}
	facts.Runtime = true
	service, _ := hvsock.ParseGUID(serviceID)
	dial := func(ctx context.Context) (net.Conn, error) {
		return hvsock.Dial(ctx, hvsock.Addr{VMID: vm, ServiceID: service})
	}
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := dial(probe)
	if err != nil {
		var errno windows.Errno
		if errors.As(err, &errno) {
			facts.DialCode = uint32(errno)
		}
		return json.NewEncoder(os.Stdout).Encode(facts)
	}
	_ = conn.Close()
	var output boundedBuffer
	if guestagent.Run(probe, dial, []string{guestBinary, "facts"}, nil, &output) == nil && json.Unmarshal(output.data, &facts.Session) == nil {
		facts.Agent = facts.Session.valid()
	}
	return json.NewEncoder(os.Stdout).Encode(facts)
}

func inventory(id string, out io.Writer) error {
	dll := windows.NewLazySystemDLL("computecore.dll")
	create, closeOp := dll.NewProc("HcsCreateOperation"), dll.NewProc("HcsCloseOperation")
	enumerate, wait := dll.NewProc("HcsEnumerateComputeSystems"), dll.NewProc("HcsWaitForOperationResult")
	op, _, _ := create.Call(0, 0)
	if op == 0 {
		return errors.New("inventory operation unavailable")
	}
	defer func() { _, _, _ = closeOp.Call(op) }()
	query, _ := windows.UTF16PtrFromString("{}")
	// #nosec G103 -- Fixed native enumeration query, no mutation.
	code, _, _ := enumerate.Call(uintptr(unsafe.Pointer(query)), op)
	if uint32(code&0xffffffff)&0x80000000 != 0 {
		return fmt.Errorf("inventory HRESULT 0x%08x", uint32(code&0xffffffff))
	}
	var result *uint16
	// #nosec G103 -- HCS writes one allocation pointer, freed below.
	code, _, _ = wait.Call(op, 10000, uintptr(unsafe.Pointer(&result)))
	if result != nil {
		// #nosec G103 -- Release only the HCS LocalAlloc result.
		defer func() { _, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(result)))) }()
	}
	if uint32(code&0xffffffff)&0x80000000 != 0 || result == nil {
		return fmt.Errorf("inventory unavailable HRESULT 0x%08x", uint32(code&0xffffffff))
	}
	var text []uint16
	for i := 0; i < 32768; i++ {
		// #nosec G103 -- Bounded UTF-16 scan of HCS's NUL-terminated allocation.
		value := *(*uint16)(unsafe.Add(unsafe.Pointer(result), i*2))
		if value == 0 {
			break
		}
		text = append(text, value)
	}
	if len(text) == 32768 {
		return errors.New("inventory exceeds bound")
	}
	var items []map[string]json.RawMessage
	if json.Unmarshal([]byte(windows.UTF16ToString(text)), &items) != nil {
		return errors.New("inventory invalid")
	}
	for _, item := range items {
		var p hcs.Properties
		data, _ := json.Marshal(item)
		if json.Unmarshal(data, &p) != nil {
			return errors.New("inventory shape invalid")
		}
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		owner := "other"
		for _, known := range []string{"WindowsSandbox", "WindowsSandboxClient", "Windows Sandbox", "Bivouac", "bivouac"} {
			if p.Owner == known {
				owner = known
			}
		}
		// Only GUID identities from Sandbox-class owners are useful here;
		// foreign HCS names can contain operator-chosen host information.
		if owner != "WindowsSandbox" && owner != "WindowsSandboxClient" && owner != "Windows Sandbox" {
			p.ID = ""
			p.RuntimeID = ""
		}
		if !validGUID(p.ID) {
			p.ID = ""
		}
		if !validGUID(p.RuntimeID) {
			p.RuntimeID = ""
		}
		facts := struct {
			ID      string   `json:"id"`
			Owner   string   `json:"owner_kind"`
			Type    string   `json:"type"`
			Runtime string   `json:"runtime"`
			Matches bool     `json:"matches"`
			Keys    []string `json:"keys"`
		}{p.ID, owner, p.SystemType, p.RuntimeID, strings.EqualFold(p.ID, id) || strings.EqualFold(p.RuntimeID, id), keys}
		if err := json.NewEncoder(out).Encode(facts); err != nil {
			return err
		}
	}
	return nil
}

type boundedBuffer struct{ data []byte }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 65536 {
		return 0, errors.New("lab output bound")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func run(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	args := os.Args[1:]
	if len(args) == 1 && (args[0] == "--help" || args[0] == "help") {
		_, err := fmt.Fprintln(os.Stdout, "sandbox-lab run --root <directory> --bivouac <exe> --runner <zip> --runner-sha256 <sha256> [--network-probe | --reverse-probe]\nsandbox-lab inspect <recorded-cli-id> | inventory <recorded-cli-id>")
		return err
	}
	if len(args) == 1 {
		switch args[0] {
		case "agent":
			return agent(parent)
		case "agent-tcp":
			return tcpAgent(parent, false)
		case "agent-reverse":
			return tcpAgent(parent, true)
		case "facts":
			return json.NewEncoder(os.Stdout).Encode(session())
		case "ownership":
			return guestOwnership()
		case "smoke":
			return guestSmoke(ctx, os.Stdout)
		case "echo":
			data, err := io.ReadAll(io.LimitReader(os.Stdin, 65))
			if err != nil {
				return errors.New("bounded echo failed")
			}
			return json.NewEncoder(os.Stdout).Encode(struct {
				Input bool `json:"input"`
			}{string(data) == "bivouac-sandbox-stdin-probe"})
		case "expected-failure":
			return errors.New("expected lab failure")
		}
	}
	if len(args) > 0 && args[0] == "run" {
		return runLab(ctx, args[1:], os.Stdout)
	}
	if len(args) == 2 && args[0] == "inspect" {
		return inspect(ctx, args[1])
	}
	if len(args) == 2 && args[0] == "inventory" {
		return inventory(args[1], os.Stdout)
	}
	if len(args) == 2 && args[0] == "inventory-report" {
		self, err := os.Executable()
		if err != nil {
			return errors.New("helper location unavailable")
		}
		out, err := os.OpenFile(filepath.Join(filepath.Dir(self), "native-inventory.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return errors.New("fresh inventory report required")
		}
		defer func() { _ = out.Close() }()
		if err := inventory(args[1], out); err != nil {
			return json.NewEncoder(out).Encode(struct {
				Failed bool `json:"failed"`
			}{true})
		}
		return nil
	}
	return errors.New("usage: sandbox-lab inspect <recorded-id> | agent | facts")
}

func execute() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return run(ctx)
}

func main() {
	if err := execute(); err != nil {
		sink := redact.NewWriter(os.Stderr)
		slog.New(slog.NewJSONHandler(sink, nil)).Error("sandbox lab failed", "error", err)
		_ = sink.Close()
		os.Exit(1)
	}
}
