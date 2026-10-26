//go:build windows

package guestagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/hvsock"
	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const installerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

type selftestBuffer struct{ bytes.Buffer }

func (b *selftestBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, errors.New("selftest output bound")
	}
	return b.Buffer.Write(p)
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
		facts := inspectTaskFacts(func(name string) (TaskFacts, error) {
			return readTaskFacts(ctx, name, user, tokenUser.User.Sid.String())
		})
		facts.OwnerTrusted, facts.ACLProtected, facts.ACLExpected = installationACL(WindowsPath)
		owner, protected, expected := installationACL(filepath.Dir(WindowsPath))
		facts.OwnerTrusted = facts.OwnerTrusted && owner
		facts.ACLProtected = facts.ACLProtected && protected
		facts.ACLExpected = facts.ACLExpected && expected
		return json.NewEncoder(out).Encode(facts)
	}
	return errors.New("invalid agent selftest")
}

// Failure of either independent query leaves fixed false predicates for that
// task, while preserving the other task's facts. No raw query error is emitted.
func inspectTaskFacts(query func(string) (TaskFacts, error)) InstallationFacts {
	agent, agentErr := query(WindowsTaskName)
	if agentErr != nil {
		agent = TaskFacts{}
	}
	runner, err := query(WindowsRunnerTaskName)
	// A descriptor-query failure may still leave useful structural facts.
	if err != nil {
		runner.TaskSecurity = false
	}
	return InstallationFacts{TaskUser: agent.TaskUser, TaskHighest: agent.TaskHighest, TaskInteractive: agent.TaskInteractive, TaskAction: agent.TaskAction, TaskPriority: agent.TaskPriority, RunnerTask: runner}
}
