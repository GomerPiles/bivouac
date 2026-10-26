//go:build windows

package guestagent

import (
	"bytes"
	"context"
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

	"golang.org/x/sys/windows"
)

type taskElement struct {
	XMLName  xml.Name
	Text     string        `xml:",chardata"`
	Children []taskElement `xml:",any"`
}

func (e taskElement) elements(name string) []taskElement {
	var found []taskElement
	for _, c := range e.Children {
		if c.XMLName.Local == name {
			found = append(found, c)
		}
	}
	return found
}
func (e taskElement) one(name string) taskElement {
	children := e.elements(name)
	if len(children) == 1 {
		return children[0]
	}
	return taskElement{}
}
func (e taskElement) value(name string) string {
	c := e.one(name)
	if len(c.Children) != 0 {
		return ""
	}
	return c.Text
}

func (e taskElement) setting(name, defaultValue string) string {
	if len(e.elements(name)) == 0 {
		return defaultValue
	}
	return e.value(name) // Duplicates and malformed explicit values never default.
}

// Bound bytes, depth and node count before decoding. Directives, duplicate
// sections and additional action types cannot disappear in struct decoding.
func taskFacts(raw []byte, name, user, sid string, resolve func(string) string) (TaskFacts, error) {
	var facts TaskFacts
	bad := errors.New("task facts unavailable")
	if len(raw) == 0 || len(raw) > 65536 {
		return facts, bad
	}
	if len(raw) > 1 && (raw[0] == 0xff && raw[1] == 0xfe || raw[1] == 0) {
		if len(raw)%2 != 0 {
			return facts, bad
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
			return nil, bad
		}
		return d
	}
	d := decoder()
	depth, nodes, roots := 0, 0, 0
	for {
		token, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return facts, bad
		}
		switch t := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			nodes++
			if depth > 16 || nodes > 512 {
				return facts, bad
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			return facts, bad
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return facts, bad
			}
		}
	}
	var task taskElement
	if roots != 1 || decoder().Decode(&task) != nil || task.XMLName.Local != "Task" {
		return facts, bad
	}
	principals := task.one("Principals")
	actions := task.one("Actions")
	if len(principals.Children) != 1 || principals.Children[0].XMLName.Local != "Principal" || len(actions.Children) != 1 || actions.Children[0].XMLName.Local != "Exec" {
		return facts, bad
	}
	p, a := principals.Children[0], actions.Children[0]
	if taskSID, err := windows.StringToSid(p.value("UserId")); err == nil {
		facts.TaskUser = taskSID.String() == sid
	} else {
		facts.TaskUser = resolve(p.value("UserId")) == sid && sid != ""
	}
	facts.TaskHighest = p.value("RunLevel") == "HighestAvailable"
	facts.TaskInteractive = p.value("LogonType") == "InteractiveToken"
	facts.TaskAction = strings.EqualFold(a.value("Command"), WindowsPath) && a.value("Arguments") == "guest-agent --user "+user
	settings := task.one("Settings")
	if settings.value("Priority") == "4" {
		facts.TaskPriority = 4
	}
	if name == WindowsRunnerTaskName {
		facts.TaskAction = strings.EqualFold(a.value("Command"), WindowsPath) && a.value("Arguments") == "guest windows detached" && strings.EqualFold(a.value("WorkingDirectory"), guestDirectory)
		// Task Scheduler settingsType schema defaults: AllowStartOnDemand and
		// Enabled=true; RunOnlyIfIdle and RunOnlyIfNetworkAvailable=false;
		// MultipleInstancesPolicy=IgnoreNew; RestartOnFailure is optional.
		// Priority defaults to 7, time limit to PT72H, both battery flags to
		// true, so those four must explicitly override their defaults.
		// https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema
		facts.TaskPolicy = len(task.elements("Triggers")) <= 1 && len(task.one("Triggers").Children) == 0 &&
			len(task.elements("Settings")) == 1 && settings.setting("MultipleInstancesPolicy", "IgnoreNew") == "IgnoreNew" && settings.value("ExecutionTimeLimit") == "PT0S" && len(settings.elements("RestartOnFailure")) == 0 &&
			settings.setting("AllowStartOnDemand", "true") == "true" && settings.setting("Enabled", "true") == "true" && settings.setting("RunOnlyIfIdle", "false") == "false" &&
			settings.setting("RunOnlyIfNetworkAvailable", "false") == "false" && settings.value("DisallowStartIfOnBatteries") == "false" && settings.value("StopIfGoingOnBatteries") == "false"
	} else if name != WindowsTaskName {
		return TaskFacts{}, bad
	}
	return facts, nil
}

// Compare effective task-object DACL entries, not a textual SDDL spelling.
func runnerTaskSecurity(text string) bool {
	sd, err := windows.SecurityDescriptorFromString(text)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || (!owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return false
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 2 {
		return false
	}
	seen := map[string]bool{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			return false
		}
		// #nosec G103 -- GetAce validates the variable-sized SID.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		key := sid.String()
		if seen[key] {
			return false
		}
		seen[key] = true
		mask := uint32(0x1f01ff)
		if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			mask = 0x1200a9
		} else if !sid.IsWellKnown(windows.WinLocalSystemSid) {
			return false
		}
		if uint32(ace.Mask) != mask {
			return false
		}
	}
	return true
}

func taskOutput(ctx context.Context, binary string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	var b selftestBuffer
	cmd.Stdout = &b
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return nil, errors.New("task facts unavailable")
	}
	return b.Bytes(), nil
}

func readTaskDefinition(ctx context.Context, name, user, sid string) (TaskFacts, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return TaskFacts{}, errors.New("task facts unavailable")
	}
	raw, err := taskOutput(ctx, filepath.Join(system, "schtasks.exe"), "/Query", "/TN", name, "/XML")
	if err != nil {
		return TaskFacts{}, err
	}
	facts, err := taskFacts(raw, name, user, sid, func(name string) string {
		sid, _, _, err := windows.LookupSID("", name)
		if err != nil {
			return ""
		}
		return sid.String()
	})
	if err != nil {
		return facts, err
	}
	return facts, nil
}

// Only installation self-test queries the current DACL. Runtime trusts the
// descriptor verified before publication of the immutable source image.
func readTaskFacts(ctx context.Context, name, user, sid string) (TaskFacts, error) {
	facts, err := readTaskDefinition(ctx, name, user, sid)
	if err != nil {
		return facts, err
	}
	if name == WindowsRunnerTaskName {
		system, err := windows.GetSystemDirectory()
		if err != nil {
			return facts, err
		}
		// Query the registered object's descriptor; XML registration metadata alone
		// does not prove that its current DACL still matches. Fixed code, no input.
		raw, err := taskOutput(ctx, filepath.Join(system, `WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop';$s=New-Object -ComObject Schedule.Service;try{$s.Connect();$f=$s.GetFolder('\');try{$t=$f.GetTask('bivouac-guest-runner');try{[Console]::Out.Write($t.GetSecurityDescriptor(5))}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($t)}}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($f)}}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($s)}`)
		if err != nil {
			facts.TaskSecurity = false
			return facts, err
		}
		facts.TaskSecurity = runnerTaskSecurity(string(raw))
	}
	return facts, nil
}

// CheckRunnerTask is the pre-marker launch proof. It never queries run state.
func CheckRunnerTask(ctx context.Context) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return errors.New("runner task unavailable")
	}
	name, _, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return errors.New("runner task unavailable")
	}
	facts, err := readTaskDefinition(ctx, WindowsRunnerTaskName, name, user.User.Sid.String())
	if err != nil || !facts.ValidDefinition() {
		return errors.New("runner task unavailable")
	}
	return nil
}
