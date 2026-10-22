//go:build windows

package winrunner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"golang.org/x/sys/windows"
)

// These hidden modes are opt-in guest lab operations, never runtime startup.
// A harmless ten-minute probe uses exactly start's precheck/marker/detachment
// path; it requires neither a runner installation nor real runner input.
type LabProbeFacts struct {
	Alive      bool `json:"alive"`
	OutsideJob bool `json:"outside_job"`
}
type labProbeRecord struct {
	Identity   listenerIdentity `json:"identity"`
	OutsideJob bool             `json:"outside_job"`
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
		f, err := root.OpenFile("jit", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("lab probe already started")
		}
		_, err = f.WriteString("harmless lab probe")
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
		if err := startChecked(root, guestagent.CheckBreakaway, func() error {
			cmd := detachedGuestCommand(self, "lab-probe")
			if cmd.Start() != nil {
				return errors.New("lab probe launch failed")
			}
			return cmd.Process.Release()
		}); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(struct {
			Started bool `json:"started"`
		}{true})
	case "lab-probe":
		inside, err := guestagent.ProcessInJob(windows.CurrentProcess())
		if err != nil {
			return errors.New("lab job proof unavailable")
		}
		identity, live, err := processIdentity(windows.GetCurrentProcessId())
		if err != nil || !live {
			return errors.New("lab identity unavailable")
		}
		if err := writeGuestJSON("lab-probe.json", labProbeRecord{identity, !inside}); err != nil {
			return err
		}
		timer := time.NewTimer(10 * time.Minute)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
		return nil
	case "lab-status":
		h, r, err := labProcess("lab-probe.json", windows.SYNCHRONIZE)
		if err != nil {
			return json.NewEncoder(out).Encode(LabProbeFacts{})
		}
		defer func() { _ = windows.CloseHandle(h) }()
		state, err := windows.WaitForSingleObject(h, 0)
		return json.NewEncoder(out).Encode(LabProbeFacts{err == nil && state == uint32(windows.WAIT_TIMEOUT), r.OutsideJob})
	case "lab-stop":
		return terminateLabProcess("lab-probe.json")
	case "lab-task-cycle", "lab-agent-cycle":
		if guestagent.CheckBreakaway() != nil {
			return errors.New("lab controller breakaway unavailable")
		}
		child, record := "lab-task-controller", "lab-task-agent.json"
		if mode == "lab-agent-cycle" {
			child, record = "lab-agent-controller", "lab-agent.json"
		}
		parent, err := labParent()
		if err != nil {
			return err
		}
		if err := writeGuestJSON(record, labProbeRecord{Identity: parent}); err != nil {
			return err
		}
		cmd := detachedGuestCommand(self, child)
		if cmd.Start() != nil {
			return errors.New("lab controller launch failed")
		}
		if err := cmd.Process.Release(); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(struct {
			Scheduled bool `json:"scheduled"`
		}{true})
	case "lab-task-controller", "lab-agent-controller":
		// Let the scheduling command's acknowledgement reach the host first.
		if pauseGuest(ctx, 2*time.Second) != nil {
			return errors.New("lab controller cancelled")
		}
		control, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if mode == "lab-task-controller" {
			err = labTask(control, "/End")
		} else {
			err = terminateLabProcess("lab-agent.json")
		}
		if err != nil {
			return err
		}
		if pauseGuest(control, time.Second) != nil {
			return errors.New("lab controller cancelled")
		}
		if err := labTask(control, "/Run"); err != nil {
			return err
		}
		record := "lab-task-complete.json"
		if mode == "lab-agent-controller" {
			record = "lab-agent-complete.json"
		}
		return writeGuestJSON(record, struct {
			Complete bool `json:"complete"`
		}{true})
	case "lab-task-result", "lab-agent-result":
		record, complete := "lab-task-agent.json", "lab-task-complete.json"
		if mode == "lab-agent-result" {
			record, complete = "lab-agent.json", "lab-agent-complete.json"
		}
		var previous labProbeRecord
		var result struct {
			Complete  bool `json:"complete"`
			Restarted bool `json:"restarted"`
		}
		data, readErr := readGuestFile(filepath.Join(guestBase, record), 4096)
		if readErr == nil && json.Unmarshal(data, &previous) == nil {
			parent, parentErr := labParent()
			result.Restarted = parentErr == nil && (parent.PID != previous.Identity.PID || parent.Creation != previous.Identity.Creation)
			data, readErr = readGuestFile(filepath.Join(guestBase, complete), 4096)
			if readErr == nil {
				var completion struct {
					Complete bool `json:"complete"`
				}
				if json.Unmarshal(data, &completion) == nil {
					result.Complete = completion.Complete
				}
			}
		}
		return json.NewEncoder(out).Encode(result)
	}
	return errors.New("invalid lab probe operation")
}
