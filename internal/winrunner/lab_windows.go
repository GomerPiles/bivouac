//go:build windows

package winrunner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"golang.org/x/sys/windows"
)

// Lab facts contain only booleans, numeric process identities and fixed tokens.
type LabProbeFacts struct {
	Alive                    bool   `json:"alive"`
	GrandchildAlive          bool   `json:"grandchild_alive"`
	InJob                    string `json:"in_job"`
	AgentInImmediateJob      string `json:"agent_in_immediate_job"`
	User                     bool   `json:"user"`
	Elevated                 bool   `json:"elevated"`
	Console                  bool   `json:"console"`
	Desktop                  bool   `json:"desktop"`
	NormalPriority           bool   `json:"normal_priority"`
	GrandchildNormalPriority bool   `json:"grandchild_normal_priority"`
	PID                      uint32 `json:"pid"`
	Creation                 uint64 `json:"creation"`
	ChildPID                 uint32 `json:"child_pid"`
	ChildCreation            uint64 `json:"child_creation"`
	GateStage                string `json:"gate_stage"`
}

func (f LabProbeFacts) Valid() bool {
	return f.Alive && f.GrandchildAlive && f.User && f.Elevated && f.Console && f.Desktop && f.NormalPriority && f.GrandchildNormalPriority && f.PID != 0 && f.Creation != 0 && f.ChildPID != 0 && f.ChildCreation != 0
}
func (f LabProbeFacts) SameTree(other LabProbeFacts) bool {
	return f.PID == other.PID && f.Creation == other.Creation && f.ChildPID == other.ChildPID && f.ChildCreation == other.ChildCreation
}

type labProbeRecord struct {
	Identity listenerIdentity `json:"identity"`
	Facts    LabProbeFacts    `json:"facts"`
}
type labCycleRequest struct {
	ID    string           `json:"id"`
	Agent listenerIdentity `json:"agent"`
}
type labCycleCompletion struct {
	ID       string           `json:"id"`
	Agent    listenerIdentity `json:"agent"`
	Complete bool             `json:"complete"`
}

func labInJob() string {
	// A successful NULL-job query proves membership in the immediate job.
	// Failure remains unavailable rather than claiming absence from all jobs.
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	// #nosec G103 -- Fixed job-limit output used synchronously.
	err := windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), nil)
	return jobQueryFact(err)
}

func jobQueryFact(err error) string {
	if err != nil {
		return "unknown"
	}
	return "true"
}

// QueryInformationJobObject(NULL) describes only the immediate job. A bounded
// incomplete list is unknown; it can never establish absence from ancestors.
func labImmediateAgent(pid uint32) string {
	type jobPIDs struct {
		Assigned, Listed uint32
		PIDs             [1024]uintptr
	}
	var list jobPIDs
	var returned uint32
	// #nosec G103 -- Fixed bounded JOBOBJECT_BASIC_PROCESS_ID_LIST buffer.
	err := windows.QueryInformationJobObject(0, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&list)), uint32(unsafe.Sizeof(list)), &returned)
	if err != nil {
		return "unknown"
	}
	return labMembership(list.Assigned, list.Listed, returned, list.PIDs[:], pid)
}

func labMembership(assigned, listed, returned uint32, pids []uintptr, pid uint32) string {
	if returned < 8 || assigned != listed || uint64(listed) > uint64(len(pids)) || uint64(returned) < 8+uint64(listed)*uint64(unsafe.Sizeof(uintptr(0))) {
		return "unknown"
	}
	for _, p := range pids[:listed] {
		if p == uintptr(pid) {
			return "true"
		}
	}
	return "false"
}

func labCycleResult(request labCycleRequest, completion labCycleCompletion, parent listenerIdentity) (bool, bool) {
	valid := validLabRequest(request) && completion.ID == request.ID && completion.Agent == request.Agent
	return valid && completion.Complete, valid && parent != request.Agent
}

func labNormalPriority(handle windows.Handle) bool {
	value, err := windows.GetPriorityClass(handle)
	return err == nil && value == windows.NORMAL_PRIORITY_CLASS
}

func readLabJSON(name string, value any) error {
	data, err := readGuestFile(filepath.Join(guestBase, name), 4096)
	if err != nil || json.Unmarshal(data, value) != nil {
		return errors.New("lab record unavailable")
	}
	return nil
}

func validateLabAgent(identity listenerIdentity) bool {
	actual, live, err := processIdentity(identity.PID)
	return err == nil && live && identity.Creation != 0 && actual == identity && strings.EqualFold(identity.Image, guestagent.WindowsPath)
}

func executeLabCycle(ctx context.Context, kind string, request labCycleRequest) labCycleCompletion {
	result := labCycleCompletion{ID: request.ID, Agent: request.Agent}
	if !validLabRequest(request) || !validateLabAgent(request.Agent) {
		return result
	}
	// The request command's acknowledgement reaches the host before its agent dies.
	if pauseGuest(ctx, 2*time.Second) != nil {
		return result
	}
	if !validateLabAgent(request.Agent) {
		return result
	}
	control, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var err error
	if kind == "task" {
		err = labTask(control, "/End")
	} else {
		// Revalidate the supplied current identity on the opened termination handle.
		err = writeGuestJSON("lab-agent.json", labProbeRecord{Identity: request.Agent})
		if err == nil {
			err = terminateLabProcess("lab-agent.json")
		}
	}
	if err != nil || pauseGuest(control, time.Second) != nil {
		return result
	}
	result.Complete = labTask(control, "/Run") == nil
	return result
}
func validLabRequest(r labCycleRequest) bool {
	if len(r.ID) != 32 {
		return false
	}
	for _, c := range r.ID {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return r.Agent.PID != 0 && r.Agent.Creation != 0 && strings.EqualFold(r.Agent.Image, guestagent.WindowsPath)
}

func labProbe(ctx context.Context) error {
	var agent labProbeRecord
	if readLabJSON("lab-agent.json", &agent) != nil || !validateLabAgent(agent.Identity) {
		return errors.New("lab agent identity unavailable")
	}
	identity, live, err := processIdentity(windows.GetCurrentProcessId())
	if err != nil || !live {
		return errors.New("lab identity unavailable")
	}
	inJob := labInJob()
	token := windows.GetCurrentProcessToken()
	nativeContext, contextErr := guestagent.ReadRunnerContext()
	// Job membership describes only this baseline snapshot. Survival and fresh
	// agent identities gate cycles; the terminated agent is never queried again.
	facts := LabProbeFacts{InJob: inJob, AgentInImmediateJob: labImmediateAgent(agent.Identity.PID), User: contextErr == nil && nativeContext.ExpectedSID != "" && nativeContext.UserSID == nativeContext.ExpectedSID, Elevated: token.IsElevated(), Desktop: runnerDesktop(), NormalPriority: labNormalPriority(windows.CurrentProcess()), PID: identity.PID, Creation: identity.Creation, GateStage: "probe-ready"}
	var session uint32
	facts.Console = windows.ProcessIdToSessionId(identity.PID, &session) == nil && session != 0 && session == windows.WTSGetActiveConsoleSessionId()
	child := runnerChildCommand(guestagent.WindowsPath, "lab-sleeper")
	if child.Start() != nil {
		return errors.New("lab grandchild unavailable")
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	done := map[string]string{}
	for ctx.Err() == nil {
		var grandchild labProbeRecord
		if readLabJSON("lab-grandchild.json", &grandchild) == nil && int64(child.Process.Pid) == int64(grandchild.Identity.PID) && validateLabAgent(grandchild.Identity) {
			facts.ChildPID, facts.ChildCreation = grandchild.Identity.PID, grandchild.Identity.Creation
			facts.GrandchildNormalPriority = grandchild.Facts.NormalPriority
		}
		if err := writeGuestJSON("lab-probe.json", labProbeRecord{Identity: identity, Facts: facts}); err != nil {
			return err
		}
		for _, kind := range []string{"task", "agent"} {
			var request labCycleRequest
			if readLabJSON("lab-"+kind+"-request.json", &request) != nil || !validLabRequest(request) || done[kind] == request.ID {
				continue
			}
			done[kind] = request.ID
			facts.GateStage = kind + "-request"
			if err := writeGuestJSON("lab-probe.json", labProbeRecord{Identity: identity, Facts: facts}); err != nil {
				return err
			}
			result := executeLabCycle(ctx, kind, request)
			facts.GateStage = "cycle-failed"
			if result.Complete {
				facts.GateStage = kind + "-complete"
			}
			if err := writeGuestJSON("lab-"+kind+"-complete.json", result); err != nil {
				return err
			}
		}
		if pauseGuest(ctx, 200*time.Millisecond) != nil {
			break
		}
	}
	return nil
}

func runLabProbe(ctx context.Context, mode string, out io.Writer) error {
	self, err := os.Executable()
	if err != nil || !strings.EqualFold(self, guestagent.WindowsPath) {
		return errors.New("lab probe requires the installed guest agent")
	}
	switch mode {
	case "lab-start":
		guard, err := guestagent.LockGuestDirectory()
		if err != nil {
			return errors.New("lab probe storage unavailable")
		}
		defer func() { _ = guard.Close() }()
		root, err := os.OpenRoot(guestBase)
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()
		parent, err := labParent()
		if err != nil {
			return err
		}
		if err := writeGuestJSON("lab-agent.json", labProbeRecord{Identity: parent}); err != nil {
			return err
		}
		jit, err := root.OpenFile("jit", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return errors.New("lab probe already started")
		}
		_, writeErr := jit.WriteString("harmless lab probe")
		if err := errors.Join(writeErr, jit.Sync(), jit.Close()); err != nil {
			return err
		}
		if err := dispatchRunner(ctx, root, "lab-probe"); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(struct {
			Started bool `json:"started"`
		}{true})
	case "lab-probe":
		return labProbe(ctx)
	case "lab-sleeper":
		identity, live, err := processIdentity(windows.GetCurrentProcessId())
		if err != nil || !live {
			return errors.New("lab grandchild identity unavailable")
		}
		if err := writeGuestJSON("lab-grandchild.json", labProbeRecord{Identity: identity, Facts: LabProbeFacts{NormalPriority: labNormalPriority(windows.CurrentProcess())}}); err != nil {
			return err
		}
		_ = pauseGuest(ctx, 10*time.Minute)
		return nil
	case "lab-status":
		h, r, err := labProcess("lab-probe.json", windows.SYNCHRONIZE)
		if err != nil {
			return json.NewEncoder(out).Encode(LabProbeFacts{})
		}
		defer func() { _ = windows.CloseHandle(h) }()
		state, err := windows.WaitForSingleObject(h, 0)
		r.Facts.Alive = err == nil && state == uint32(windows.WAIT_TIMEOUT)
		r.Facts.NormalPriority = labNormalPriority(h)
		hChild, child, err := labProcess("lab-grandchild.json", windows.SYNCHRONIZE)
		if err == nil {
			state, err := windows.WaitForSingleObject(hChild, 0)
			r.Facts.GrandchildNormalPriority = labNormalPriority(hChild)
			_ = windows.CloseHandle(hChild)
			r.Facts.GrandchildAlive = err == nil && state == uint32(windows.WAIT_TIMEOUT) && child.Identity.PID == r.Facts.ChildPID && child.Identity.Creation == r.Facts.ChildCreation
		}
		return json.NewEncoder(out).Encode(r.Facts)
	case "lab-stop":
		return errors.Join(terminateLabProcess("lab-grandchild.json"), terminateLabProcess("lab-probe.json"))
	case "lab-task-cycle", "lab-agent-cycle":
		kind := "task"
		if mode == "lab-agent-cycle" {
			kind = "agent"
		}
		parent, err := labParent()
		if err != nil {
			return err
		}
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		request := labCycleRequest{ID: hex.EncodeToString(id[:]), Agent: parent}
		if err := writeGuestJSON("lab-"+kind+"-request.json", request); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(struct {
			Scheduled bool   `json:"scheduled"`
			ID        string `json:"id"`
		}{true, request.ID})
	case "lab-task-result", "lab-agent-result":
		kind := "task"
		if mode == "lab-agent-result" {
			kind = "agent"
		}
		var request labCycleRequest
		var completion labCycleCompletion
		parent, err := labParent()
		complete, restarted := false, false
		if err == nil && readLabJSON("lab-"+kind+"-request.json", &request) == nil && readLabJSON("lab-"+kind+"-complete.json", &completion) == nil {
			complete, restarted = labCycleResult(request, completion, parent)
		}
		return json.NewEncoder(out).Encode(struct {
			Complete  bool   `json:"complete"`
			Restarted bool   `json:"restarted"`
			ID        string `json:"id"`
		}{complete, restarted, completion.ID})
	}
	return errors.New("invalid lab probe operation")
}

func labParent() (listenerIdentity, error) {
	pid := os.Getppid()
	if pid <= 0 {
		return listenerIdentity{}, errors.New("lab parent unavailable")
	}
	parent, live, err := processIdentity(uint32(pid)) // #nosec G115 -- Windows PID fits DWORD.
	if err != nil || !live || !strings.EqualFold(parent.Image, guestagent.WindowsPath) {
		return listenerIdentity{}, errors.New("lab parent identity unavailable")
	}
	return parent, nil
}

func labProcess(record string, access uint32) (windows.Handle, labProbeRecord, error) {
	var r labProbeRecord
	data, err := readGuestFile(filepath.Join(guestBase, record), 4096)
	if err != nil || json.Unmarshal(data, &r) != nil || r.Identity.PID == 0 || r.Identity.Creation == 0 || !strings.EqualFold(r.Identity.Image, guestagent.WindowsPath) {
		return 0, r, errors.New("lab process identity unavailable")
	}
	handle, err := windows.OpenProcess(access|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, r.Identity.PID)
	if err != nil {
		return 0, r, errors.New("lab process unavailable")
	}
	actual, err := identityFromHandle(r.Identity.PID, handle)
	if err != nil || actual != r.Identity {
		_ = windows.CloseHandle(handle)
		return 0, r, errors.New("lab process identity changed")
	}
	return handle, r, nil
}

func terminateLabProcess(record string) error {
	handle, _, err := labProcess(record, windows.PROCESS_TERMINATE|windows.SYNCHRONIZE)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	if windows.TerminateProcess(handle, 0) != nil {
		return errors.New("lab process termination failed")
	}
	state, err := windows.WaitForSingleObject(handle, 5000)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		return errors.New("lab process termination unconfirmed")
	}
	return nil
}

func labTask(ctx context.Context, operation string) error {
	if operation != "/End" && operation != "/Run" {
		return errors.New("invalid lab task operation")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return errors.New("lab task unavailable")
	}
	cmd := exec.CommandContext(ctx, filepath.Join(system, "schtasks.exe"), operation, "/TN", guestagent.WindowsTaskName)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if cmd.Run() != nil {
		return errors.New("lab task operation failed")
	}
	return nil
}
