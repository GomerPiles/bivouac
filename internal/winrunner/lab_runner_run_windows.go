//go:build windows

package winrunner

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"golang.org/x/sys/windows"
)

// LabRunnerRunFacts says whether the configured account, without its
// administrator rights, is refused starting the elevated runner task. The lab
// asks while the probe holds the task: under IgnoreNew an accepted run starts
// nothing, so only the exit status differs. schtasks exits 1 for any error, so
// the same token must also read the agent task, which keeps Task Scheduler's
// default read entry for its principal: that proves schtasks works under the
// token and that the runner refusals are about access. AgentRunAccepted is a
// diagnostic of why the runner task omits that entry (a task's own user may
// run a task it can read); it does not gate.
type LabRunnerRunFacts struct {
	FilteredToken      bool `json:"filtered_token"`
	AgentQueryAccepted bool `json:"agent_query_accepted"`
	RunnerQueryRefused bool `json:"runner_query_refused"`
	FilteredRefused    bool `json:"filtered_refused"`
	ElevatedAccepted   bool `json:"elevated_accepted"`
	AgentRunAccepted   bool `json:"agent_run_accepted"`
}

func (f LabRunnerRunFacts) Valid() bool {
	return f.FilteredToken && f.AgentQueryAccepted && f.RunnerQueryRefused && f.FilteredRefused && f.ElevatedAccepted
}

func labRunnerRun(ctx context.Context) LabRunnerRunFacts {
	var f LabRunnerRunFacts
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return f
	}
	schtasks := filepath.Join(system, "schtasks.exe")
	args := []string{"/Run", "/TN", guestagent.WindowsRunnerTaskName}
	if token, err := labFilteredToken(); err == nil {
		f.FilteredToken = labTokenFiltered(token)
		if f.FilteredToken {
			run := func(args ...string) (bool, bool) {
				code, err := runWithToken(ctx, token, schtasks, args)
				return err == nil && code == 0, err == nil && code != 0
			}
			f.AgentQueryAccepted, _ = run("/Query", "/TN", guestagent.WindowsTaskName)
			_, f.RunnerQueryRefused = run("/Query", "/TN", guestagent.WindowsRunnerTaskName)
			_, f.FilteredRefused = run(args...)
			// The agent is running and its task uses IgnoreNew: nothing starts.
			f.AgentRunAccepted, _ = run("/Run", "/TN", guestagent.WindowsTaskName)
		}
		_ = token.Close()
	}
	cmd := exec.CommandContext(ctx, schtasks, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	f.ElevatedAccepted = cmd.Run() == nil
	return f
}

// labFilteredToken derives a SAFER "normal user" token from this process's
// token, at medium integrity: same user, Administrators deny-only.
func labFilteredToken() (windows.Token, error) {
	advapi := windows.NewLazySystemDLL("advapi32.dll")
	const scopeUser, levelNormalUser, levelOpen = 2, 0x20000, 1
	var level windows.Handle
	// #nosec G103 -- SaferCreateLevel writes one handle synchronously.
	if ok, _, _ := advapi.NewProc("SaferCreateLevel").Call(scopeUser, levelNormalUser, levelOpen, uintptr(unsafe.Pointer(&level)), 0); ok == 0 {
		return 0, errors.New("filtered level unavailable")
	}
	defer func() { _, _, _ = advapi.NewProc("SaferCloseLevel").Call(uintptr(level)) }()
	var token windows.Token
	// #nosec G103 -- SaferComputeTokenFromLevel writes one handle synchronously.
	if ok, _, _ := advapi.NewProc("SaferComputeTokenFromLevel").Call(uintptr(level), 0, uintptr(unsafe.Pointer(&token)), 0, 0); ok == 0 {
		return 0, errors.New("filtered token unavailable")
	}
	medium, err := windows.CreateWellKnownSid(windows.WinMediumLabelSid)
	if err != nil {
		_ = token.Close()
		return 0, err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	// #nosec G103 -- Fixed label structure used synchronously.
	if err := windows.SetTokenInformation(token, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), label.Size()); err != nil {
		_ = token.Close()
		return 0, err
	}
	return token, nil
}

// labTokenFiltered proves the token is this account's, at medium integrity,
// holding Administrators only for deny. A SAFER token derived from an elevated
// token keeps that token's elevation type (observed on Windows 11 26300), so
// the elevation flag is not checked. The UAC-filtered linked token itself
// cannot start a process without TCB privilege, and holds no more access than
// this token; a scheduler that trusted the elevation type would accept this
// token and fail the gate, never pass it.
func labTokenFiltered(token windows.Token) bool {
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	user, err := token.GetTokenUser()
	if err != nil || !user.User.Sid.Equals(self.User.Sid) || !labMediumIntegrity(token) {
		return false
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 && g.Attributes&windows.SE_GROUP_ENABLED == 0
		}
	}
	return false
}

func labMediumIntegrity(token windows.Token) bool {
	var n uint32
	_ = windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 || n > 256 {
		return false
	}
	b := make([]byte, n)
	if windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &b[0], n, &n) != nil {
		return false
	}
	// #nosec G103 -- The buffer holds one TOKEN_MANDATORY_LABEL of length n.
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&b[0]))
	medium, err := windows.CreateWellKnownSid(windows.WinMediumLabelSid)
	return err == nil && label.Label.Sid != nil && label.Label.Sid.Equals(medium)
}

// runWithToken runs a fixed argv under token, with no window or inherited handles, and
// returns its exit code, bounded at 20 seconds.
func runWithToken(ctx context.Context, token windows.Token, binary string, args []string) (uint32, error) {
	application, err := windows.UTF16PtrFromString(binary)
	if err != nil {
		return 0, err
	}
	quoted := []string{windows.EscapeArg(binary)}
	for _, arg := range args {
		quoted = append(quoted, windows.EscapeArg(arg))
	}
	command, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return 0, err
	}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Flags: windows.STARTF_USESHOWWINDOW, ShowWindow: windows.SW_HIDE}
	var p windows.ProcessInformation
	if err := windows.CreateProcessAsUser(token, application, command, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, &startup, &p); err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(p.Thread); _ = windows.CloseHandle(p.Process) }()
	limit := uint32(20000)
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left < 20*time.Second {
			limit = uint32(max(left, 0) / time.Millisecond)
		}
	}
	state, err := windows.WaitForSingleObject(p.Process, limit)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		_ = windows.TerminateProcess(p.Process, 1)
		return 0, errors.New("filtered run did not finish")
	}
	var code uint32
	if err := windows.GetExitCodeProcess(p.Process, &code); err != nil {
		return 0, err
	}
	return code, nil
}
