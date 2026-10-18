//go:build windows

package hcsspike

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Fixed read-only queries; no event text, process identity or absolute timestamp
// enters the public report. Clock changes suppress event-time subtraction.
//
//go:embed boot_events_common.ps1
var bootEventsCommon string

//go:embed boot_events_task.ps1
var bootEventsTask string

//go:embed boot_events_shell.ps1
var bootEventsShell string

type BootEvents struct {
	BootMatched        bool    `json:"boot_matched"`
	ClockStable        bool    `json:"clock_stable"`
	TaskLogEnabled     bool    `json:"task_log_enabled"`
	TaskQueryComplete  bool    `json:"task_query_complete"`
	ShellLogEnabled    bool    `json:"shell_log_enabled"`
	ShellQueryComplete bool    `json:"shell_query_complete"`
	TaskStartMS        *uint64 `json:"task_start_ms,omitempty"`
	ProcessCreatedMS   *uint64 `json:"process_created_ms,omitempty"`
	ActionStartMS      *uint64 `json:"action_start_ms,omitempty"`
	EngineReadyMS      *uint64 `json:"engine_ready_ms,omitempty"`
	ShellStartMS       *uint64 `json:"shell_start_ms,omitempty"`
	ShellReadyMS       *uint64 `json:"shell_ready_ms,omitempty"`
}

// The boot marker binds two in-memory responses to one boot. It is deliberately
// not a field of BootEvents and never reaches report JSON, state or errors.
type bootEventSnapshot struct {
	BootMarker       uint64  `json:"boot_marker"`
	ClockStable      bool    `json:"clock_stable"`
	LogEnabled       bool    `json:"log_enabled"`
	QueryComplete    bool    `json:"query_complete"`
	TaskStartMS      *uint64 `json:"task_start_ms"`
	ProcessCreatedMS *uint64 `json:"process_created_ms"`
	ActionStartMS    *uint64 `json:"action_start_ms"`
	EngineReadyMS    *uint64 `json:"engine_ready_ms"`
	ShellStartMS     *uint64 `json:"shell_start_ms"`
	ShellReadyMS     *uint64 `json:"shell_ready_ms"`
}

func parseBootEventSnapshot(b []byte) (bootEventSnapshot, error) {
	var r bootEventSnapshot
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, errors.New("invalid bounded boot event response")
	}
	if d.Decode(new(any)) != io.EOF || r.BootMarker > 3155378975999999999 || (r.ClockStable && r.BootMarker == 0) {
		return r, errors.New("invalid boot event identity")
	}
	for _, v := range []*uint64{r.TaskStartMS, r.ProcessCreatedMS, r.ActionStartMS, r.EngineReadyMS, r.ShellStartMS, r.ShellReadyMS} {
		if v != nil && (*v > 600000 || !r.ClockStable) {
			return r, errors.New("invalid boot event offset or changed clock")
		}
	}
	return r, nil
}

func bootEventCommand(script string) string {
	// Only embedded source is encoded. No configuration or guest-supplied value
	// is interpolated into the remote command.
	return "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encodedPowerShell(strings.ReplaceAll(bootEventsCommon+script, "\r\n", "\n"))
}

func joinBootEvents(task, shell bootEventSnapshot) *BootEvents {
	r := &BootEvents{BootMatched: task.BootMarker != 0 && task.BootMarker == shell.BootMarker, TaskLogEnabled: task.LogEnabled, TaskQueryComplete: task.QueryComplete, ShellLogEnabled: shell.LogEnabled, ShellQueryComplete: shell.QueryComplete}
	r.ClockStable = r.BootMatched && task.ClockStable && shell.ClockStable
	if r.ClockStable {
		r.TaskStartMS = task.TaskStartMS
		r.ProcessCreatedMS = task.ProcessCreatedMS
		r.ActionStartMS = task.ActionStartMS
		r.EngineReadyMS = shell.EngineReadyMS
		r.ShellStartMS = shell.ShellStartMS
		r.ShellReadyMS = shell.ShellReadyMS
	}
	return r
}

func (a *native) collectBootEvents(ctx context.Context, client *ssh.Client, c Config, runtimeID string) (*BootEvents, error) {
	traceCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var snapshots [2]bootEventSnapshot
	for i, script := range []string{bootEventsTask, bootEventsShell} {
		if err := a.verify(traceCtx, c, runtimeID); err != nil {
			return nil, err
		}
		out, _, err := runGuestSSH(traceCtx, client, bootEventCommand(script), nil)
		if err != nil {
			return nil, errors.New("fixed read-only boot event query failed")
		}
		snapshots[i], err = parseBootEventSnapshot(out)
		clear(out)
		if err != nil {
			return nil, err
		}
	}
	return joinBootEvents(snapshots[0], snapshots[1]), nil
}
