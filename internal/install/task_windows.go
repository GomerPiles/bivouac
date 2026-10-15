//go:build windows

// Package install registers an optional per-user login task. Foreground use
// requires no task, service, PATH change, or automatic privileged startup.
package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"

	"github.com/GomerPiles/bivouac/internal/paths"
	"github.com/GomerPiles/bivouac/internal/state"
	"golang.org/x/sys/windows"
)

// Paths are the files install touches. The manager already writes its own log.
type Paths struct {
	Binary string
	LogDir string
}

type taskRecord struct {
	Name       string `json:"name"`
	SID        string `json:"sid"`
	Home       string `json:"home"`
	XML        string `json:"xml"`
	PendingXML string `json:"pending_xml,omitempty"`
}

// Task Scheduler fills in defaults. Compare the intended effective definition,
// rather than its XML formatting, and reject additional actions or triggers.
type taskDefinition struct {
	XMLName     xml.Name        `xml:"http://schemas.microsoft.com/windows/2004/02/mit/task Task"`
	Version     string          `xml:"version,attr"`
	Description string          `xml:"RegistrationInfo>Description"`
	Principals  []taskPrincipal `xml:"Principals>Principal"`
	Triggers    []taskTrigger   `xml:"Triggers>LogonTrigger"`
	Actions     []taskAction    `xml:"Actions>Exec"`
	Settings    taskSettings    `xml:"Settings"`
}
type taskPrincipal struct {
	ID    string `xml:"id,attr"`
	User  string `xml:"UserId"`
	Logon string `xml:"LogonType"`
	Level string `xml:"RunLevel"`
}
type taskTrigger struct {
	User    string `xml:"UserId"`
	Enabled string `xml:"Enabled"`
	Delay   string `xml:"Delay"`
}
type taskAction struct {
	Command   string `xml:"Command"`
	Arguments string `xml:"Arguments"`
	Directory string `xml:"WorkingDirectory"`
}
type taskSettings struct {
	Instances     string `xml:"MultipleInstancesPolicy"`
	Battery       bool   `xml:"DisallowStartIfOnBatteries"`
	StopBattery   bool   `xml:"StopIfGoingOnBatteries"`
	HardTerminate bool   `xml:"AllowHardTerminate"`
	OnDemand      bool   `xml:"AllowStartOnDemand"`
	Enabled       bool   `xml:"Enabled"`
	Limit         string `xml:"ExecutionTimeLimit"`
	Restart       struct {
		Interval string `xml:"Interval"`
		Count    int    `xml:"Count"`
	} `xml:"RestartOnFailure"`
}

func taskIdentity() (taskRecord, string, error) {
	l, err := paths.Resolve()
	if err != nil {
		return taskRecord{}, "", err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return taskRecord{}, "", err
	}
	dir, err := filepath.Abs(l.State)
	if err != nil {
		return taskRecord{}, "", err
	}
	home := os.Getenv("BIVOUAC_HOME")
	if home != "" {
		home, err = filepath.Abs(home)
		if err != nil {
			return taskRecord{}, "", err
		}
	}
	sid := user.User.Sid.String()
	hash := sha256.Sum256([]byte(sid + "\x00" + strings.ToLower(filepath.Clean(dir))))
	return taskRecord{Name: fmt.Sprintf("Bivouac-%x", hash[:12]), SID: sid, Home: home}, filepath.Join(dir, "login-task.json"), nil
}

func taskXML(r taskRecord, binaryPath string) (string, error) {
	d := taskDefinition{
		Version:     "1.4",
		XMLName:     xml.Name{Local: "Task", Space: "http://schemas.microsoft.com/windows/2004/02/mit/task"},
		Description: "Bivouac optional login manager: " + r.Name,
		Principals:  []taskPrincipal{{ID: "manager", User: r.SID, Logon: "InteractiveToken", Level: "LeastPrivilege"}},
		Triggers:    []taskTrigger{{User: r.SID, Enabled: "true", Delay: "PT30S"}},
		Actions:     []taskAction{{Command: binaryPath, Arguments: "login-run " + syscall.EscapeArg(r.Home), Directory: filepath.Dir(binaryPath)}},
		Settings:    taskSettings{Instances: "IgnoreNew", OnDemand: true, Enabled: true, Limit: "PT0S"},
	}
	d.Settings.Restart.Interval = "PT1M"
	d.Settings.Restart.Count = 3
	data, err := xml.Marshal(d)
	// COM receives a UTF-16 BSTR, not a UTF-8 file. Omit the XML encoding
	// declaration so Task Scheduler interprets the native string correctly.
	return strings.Replace(string(data), "<Actions>", `<Actions Context="manager">`, 1), err
}

// Reject unexpected children, including non-Exec actions and other triggers,
// that would otherwise be silently discarded by encoding/xml.
func sameTask(expected, actual string) bool {
	a, err := parseTask(expected)
	if err != nil {
		return false
	}
	b, err := parseTask(actual)
	if err != nil {
		return false
	}
	if a.Description != b.Description || a.Settings != b.Settings || len(a.Principals) != 1 || len(b.Principals) != 1 || a.Principals[0] != b.Principals[0] || len(a.Triggers) != 1 || len(b.Triggers) != 1 || a.Triggers[0] != b.Triggers[0] || len(a.Actions) != 1 || len(b.Actions) != 1 || a.Actions[0] != b.Actions[0] {
		return false
	}
	decoder := taskDecoder(actual)
	var parent []string
	for {
		token, err := decoder.Token()
		if err != nil {
			return errors.Is(err, io.EOF)
		}
		switch element := token.(type) {
		case xml.StartElement:
			if element.Name.Local == "Actions" {
				for _, attribute := range element.Attr {
					if attribute.Name.Local == "Context" && attribute.Value != "manager" {
						return false
					}
				}
			}
			if len(parent) > 0 {
				switch parent[len(parent)-1] {
				case "Actions":
					if element.Name.Local != "Exec" {
						return false
					}
				case "Triggers":
					if element.Name.Local != "LogonTrigger" {
						return false
					}
				case "Principals":
					if element.Name.Local != "Principal" {
						return false
					}
				}
			}
			parent = append(parent, element.Name.Local)
		case xml.EndElement:
			parent = parent[:len(parent)-1]
		}
	}
}

func taskDecoder(s string) *xml.Decoder {
	d := xml.NewDecoder(strings.NewReader(s))
	// Native COM XML declares UTF-16 although JSON has already decoded its
	// BSTR into a Go string. Never apply a second character conversion.
	d.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		if strings.EqualFold(charset, "UTF-16") {
			return input, nil
		}
		return nil, errors.New("unexpected task XML encoding")
	}
	return d
}

func parseTask(s string) (taskDefinition, error) {
	d := taskDefinition{Settings: taskSettings{OnDemand: true, Enabled: true}}
	if err := taskDecoder(s).Decode(&d); err != nil {
		return d, err
	}
	for i := range d.Principals {
		if d.Principals[i].Level == "" {
			d.Principals[i].Level = "LeastPrivilege"
		}
	}
	for i := range d.Triggers {
		if d.Triggers[i].Enabled == "" {
			d.Triggers[i].Enabled = "true"
		}
		if !strings.HasPrefix(d.Triggers[i].User, "S-1-") {
			sid, _, _, err := windows.LookupSID("", d.Triggers[i].User)
			if err != nil {
				return d, err
			}
			d.Triggers[i].User = sid.String()
		}
	}
	return d, nil
}

// Install is opt-in and never changes durable CI mode or launches a VM. It
// refuses elevation and does not arrange the privileged engine/broker startup.
func Install(ctx context.Context, p Paths) (string, error) {
	if windows.GetCurrentProcessToken().IsElevated() {
		return "", errors.New("install the login manager from a non-elevated shell")
	}
	r, path, err := taskIdentity()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(p.Binary) {
		return "", errors.New("login binary must be an absolute path")
	}
	if _, err = os.Stat(p.Binary); err != nil {
		return "", err
	}
	r.XML, err = taskXML(r, p.Binary)
	if err != nil {
		return "", err
	}
	old, err := readTaskRecord(path, r)
	if err != nil {
		return "", err
	}
	live, err := scheduler(ctx, "query", r.Name, "", "")
	if err != nil {
		return "", err
	}
	if live != "" && (old == nil || !recordMatches(*old, live)) {
		return "", errors.New("login task exists without matching ownership; refusing replacement")
	}
	// Commit intent before native creation; keep it on failure for retry.
	if live == "" {
		if err = writeTaskRecord(path, r); err != nil {
			return "", err
		}
	} else {
		old.PendingXML = r.XML
		if err = writeTaskRecord(path, *old); err != nil {
			return "", err
		}
	}
	if _, err = scheduler(ctx, "register", r.Name, r.XML, live); err != nil {
		return "", err
	}
	if err = writeTaskRecord(path, r); err != nil {
		return "", err
	}
	return r.Name, nil
}

func readTaskRecord(path string, expected taskRecord) (*taskRecord, error) {
	data, err := state.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r taskRecord
	if json.Unmarshal(data, &r) != nil || r.Name != expected.Name || r.SID != expected.SID || r.Home != expected.Home || r.XML == "" {
		return nil, errors.New("login task ownership record differs")
	}
	return &r, nil
}
func writeTaskRecord(path string, r taskRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return state.WriteAtomic(path, data, 0o600)
}
func recordMatches(r taskRecord, live string) bool {
	return sameTask(r.XML, live) || (r.PendingXML != "" && sameTask(r.PendingXML, live))
}
func ownedTask(ctx context.Context) (taskRecord, string, string, error) {
	r, path, err := taskIdentity()
	if err != nil {
		return r, "", "", err
	}
	old, err := readTaskRecord(path, r)
	if err != nil {
		return r, path, "", err
	}
	live, err := scheduler(ctx, "query", r.Name, "", "")
	if err != nil {
		return r, path, "", err
	}
	if live != "" && (old == nil || !recordMatches(*old, live)) {
		return r, path, "", errors.New("login task ownership or definition differs")
	}
	return r, path, live, nil
}

// Uninstall removes only the recorded matching task. It never terminates an
// active manager or guest; use off/stop for those explicit lifecycle changes.
func Uninstall(ctx context.Context) error {
	r, path, live, err := ownedTask(ctx)
	if err != nil {
		return err
	}
	if live != "" {
		if _, err = scheduler(ctx, "delete", r.Name, "", live); err != nil {
			return err
		}
	}
	if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Kickstart requests the scheduler's limited interactive token, never elevation.
func Kickstart(ctx context.Context) error {
	r, _, live, err := ownedTask(ctx)
	if err != nil {
		return err
	}
	if live == "" {
		return errors.New("login task is not installed")
	}
	_, err = scheduler(ctx, "run", r.Name, "", live)
	return err
}

// Installed checks both the durable record and the native effective definition.
func Installed(ctx context.Context) (string, bool, error) {
	r, _, live, err := ownedTask(ctx)
	return r.Name, live != "", err
}

const schedulerScript = `
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$p=[Console]::In.ReadToEnd() | ConvertFrom-Json
$service=New-Object -ComObject Schedule.Service
$service.Connect()
$folder=$service.GetFolder('\')
$task=$null
try { $task=$folder.GetTask($p.Name) } catch {
 if ($_.Exception.HResult -ne -2147024894) { throw }
}
$actual=''
if ($null -ne $task) { $actual=$task.Xml }
if ($p.Operation -eq 'query') {
 [Console]::Out.Write((ConvertTo-Json -InputObject $actual -Compress)); exit 0
}
if ($actual -cne $p.Expected) { throw 'Task changed since ownership verification' }
switch ($p.Operation) {
 'register' { $null=$folder.RegisterTask($p.Name,$p.XML,6,$null,$null,3,$null) }
 'run' { if ($null -eq $task) { throw 'Task missing' }; $null=$task.Run($null) }
 'delete' { if ($null -ne $task) { $folder.DeleteTask($p.Name,0) } }
 default { throw 'Unknown operation' }
}
[Console]::Out.Write('""')
`

func scheduler(ctx context.Context, operation, name, definition, expected string) (string, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	units := utf16.Encode([]rune(schedulerScript))
	encoded := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:], u)
	}
	payload, err := json.Marshal(struct{ Operation, Name, XML, Expected string }{operation, name, definition, expected})
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("windows login task %s failed: %w", operation, err)
	}
	var result string
	if json.Unmarshal(bytes.TrimPrefix(out, []byte{0xef, 0xbb, 0xbf}), &result) != nil {
		return "", errors.New("invalid Windows login task response")
	}
	return result, nil
}
