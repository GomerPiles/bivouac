//go:build windows

package guestagent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/hvsock"
	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const WindowsTaskName = "bivouac-guest-agent"
const installerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// Selftests are hidden, guest-local lab commands. Only fixed facts cross the
// agent connection; raw task XML, account identifiers and ACLs never do.
type InstallationFacts struct {
	TaskUser        bool   `json:"task_user"`
	TaskHighest     bool   `json:"task_highest"`
	TaskInteractive bool   `json:"task_interactive"`
	TaskAction      bool   `json:"task_action"`
	TaskPriority    uint32 `json:"task_priority"`
	OwnerTrusted    bool   `json:"owner_trusted"`
	ACLProtected    bool   `json:"acl_protected"`
	ACLExpected     bool   `json:"acl_expected"`
}

func (f InstallationFacts) Valid() bool {
	return f.TaskUser && f.TaskHighest && f.TaskInteractive && f.TaskAction && f.TaskPriority == 4 && f.OwnerTrusted && f.ACLProtected && f.ACLExpected
}

type selftestBuffer struct{ bytes.Buffer }

func (b *selftestBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, errors.New("selftest output bound")
	}
	return b.Buffer.Write(p)
}

func taskFacts(raw []byte, user, sid string, resolve func(string) string) (InstallationFacts, error) {
	var facts InstallationFacts
	if len(raw) == 0 || len(raw) > 65536 {
		return facts, errors.New("task facts unavailable")
	}
	if len(raw) > 1 && (raw[0] == 0xff && raw[1] == 0xfe || raw[1] == 0) {
		if len(raw)%2 != 0 {
			return facts, errors.New("task facts unavailable")
		}
		words := make([]uint16, 0, len(raw)/2)
		for i := 0; i < len(raw); i += 2 {
			words = append(words, uint16(raw[i])|uint16(raw[i+1])<<8)
		}
		raw = []byte(strings.TrimPrefix(string(utf16.Decode(words)), "\ufeff"))
	}
	decoder := func() *xml.Decoder {
		d := xml.NewDecoder(bytes.NewReader(raw))
		d.CharsetReader = func(label string, r io.Reader) (io.Reader, error) {
			if strings.EqualFold(label, "UTF-16") || strings.EqualFold(label, "UTF-8") {
				return r, nil
			}
			return nil, errors.New("task encoding")
		}
		return d
	}
	d := decoder()
	for {
		token, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return facts, errors.New("task facts unavailable")
		}
		if _, ok := token.(xml.Directive); ok {
			return facts, errors.New("task facts unavailable")
		}
	}
	var task struct {
		Principals []struct {
			UserID    string `xml:"UserId"`
			LogonType string
			RunLevel  string
		} `xml:"Principals>Principal"`
		Actions []struct {
			Command   string
			Arguments string
		} `xml:"Actions>Exec"`
		Priority uint32 `xml:"Settings>Priority"`
	}
	if decoder().Decode(&task) != nil || len(task.Principals) != 1 || len(task.Actions) != 1 {
		return facts, errors.New("task facts unavailable")
	}
	p := task.Principals[0]
	a := task.Actions[0]
	facts.TaskUser = resolve(p.UserID) == sid
	facts.TaskHighest = p.RunLevel == "HighestAvailable"
	facts.TaskInteractive = p.LogonType == "InteractiveToken"
	facts.TaskAction = strings.EqualFold(a.Command, WindowsPath) && a.Arguments == "guest-agent --user "+user
	facts.TaskPriority = task.Priority
	return facts, nil
}

func installationACL(path string) (owner, protected, expected bool) {
	text, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	attributes, err := windows.GetFileAttributes(text)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return
	}
	return installationSecurity(sd)
}

func installationSecurity(sd *windows.SECURITY_DESCRIPTOR) (owner, protected, expected bool) {
	sid, _, err := sd.Owner()
	if err != nil {
		return
	}
	owner = sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.String() == installerSID
	control, _, err := sd.Control()
	if err != nil {
		return
	}
	protected = control&windows.SE_DACL_PROTECTED != 0
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 4 {
		return
	}
	seen := map[string]bool{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return
		}
		// #nosec G103 -- GetAce returns the validated variable-sized SID.
		s := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		key := s.String()
		if seen[key] {
			return
		}
		seen[key] = true
		mask := uint32(0x1f01ff)
		if s.IsWellKnown(windows.WinBuiltinUsersSid) {
			mask = 0x1200a9
		} else if !s.IsWellKnown(windows.WinLocalSystemSid) && !s.IsWellKnown(windows.WinBuiltinAdministratorsSid) && key != installerSID {
			return
		}
		if uint32(ace.Mask) != mask {
			return
		}
	}
	expected = true
	return
}

func selftest(ctx context.Context, args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("invalid agent selftest")
	}
	switch args[0] {
	case "loopback":
		vm, _ := hvsock.ParseGUID(winio.HvsockGUIDLoopback().String())
		service, _ := hvsock.ParseGUID(ServiceID)
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		conn, err := hvsock.Dial(attempt, hvsock.Addr{VMID: vm, ServiceID: service})
		if conn != nil {
			_ = conn.Close()
		}
		refused := errors.Is(err, windows.WSAEACCES) || errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.WSAECONNREFUSED)
		return json.NewEncoder(out).Encode(struct {
			Refused bool `json:"loopback_refused"`
		}{refused})
	case "inspect":
		tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return errors.New("agent selftest unavailable")
		}
		user, _, _, err := tokenUser.User.Sid.LookupAccount("")
		if err != nil {
			return errors.New("agent selftest unavailable")
		}
		system, err := windows.GetSystemDirectory()
		if err != nil {
			return errors.New("agent selftest unavailable")
		}
		cmd := exec.CommandContext(ctx, filepath.Join(system, "schtasks.exe"), "/Query", "/TN", WindowsTaskName, "/XML")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
		var b selftestBuffer
		cmd.Stdout = &b
		cmd.Stderr = io.Discard
		if cmd.Run() != nil {
			return errors.New("task facts unavailable")
		}
		facts, err := taskFacts(b.Bytes(), user, tokenUser.User.Sid.String(), func(name string) string {
			sid, _, _, err := windows.LookupSID("", name)
			if err != nil {
				return ""
			}
			return sid.String()
		})
		if err != nil {
			return err
		}
		facts.OwnerTrusted, facts.ACLProtected, facts.ACLExpected = installationACL(WindowsPath)
		owner, protected, expected := installationACL(filepath.Dir(WindowsPath))
		facts.OwnerTrusted = facts.OwnerTrusted && owner
		facts.ACLProtected = facts.ACLProtected && protected
		facts.ACLExpected = facts.ACLExpected && expected
		return json.NewEncoder(out).Encode(facts)
	}
	return errors.New("invalid agent selftest")
}
