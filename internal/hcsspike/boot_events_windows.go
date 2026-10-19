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

//go:embed boot_events_clock.ps1
var bootEventsClock string

type BootEvents struct {
	UptimeAtQueryMS         *uint64 `json:"uptime_at_query_ms,omitempty"`
	EventClockAtQueryMS     *uint64 `json:"event_clock_at_query_ms,omitempty"`
	ClockSampleSpanMS       *uint64 `json:"clock_sample_span_ms,omitempty"`
	ConsoleEventCount       *uint64 `json:"console_event_count,omitempty"`
	TaskProcessIsPowerShell *bool   `json:"task_process_is_powershell,omitempty"`
	BootMatched             bool    `json:"boot_matched"`
	ClockStable             bool    `json:"clock_stable"`
	TaskLogEnabled          bool    `json:"task_log_enabled"`
	TaskQueryComplete       bool    `json:"task_query_complete"`
	ShellLogEnabled         bool    `json:"shell_log_enabled"`
	ShellQueryComplete      bool    `json:"shell_query_complete"`
	TaskStartMS             *uint64 `json:"task_start_ms,omitempty"`
	ProcessCreatedMS        *uint64 `json:"process_created_ms,omitempty"`
	ActionStartMS           *uint64 `json:"action_start_ms,omitempty"`
	ShellStartMS            *uint64 `json:"shell_start_ms,omitempty"`
	ShellReadyMS            *uint64 `json:"shell_ready_ms,omitempty"`
}

// The boot marker binds three in-memory responses to one boot. It is deliberately
// not a field of BootEvents and never reaches report JSON, state or errors.
type bootEventSnapshot struct {
	UptimeAtQueryMS         *uint64 `json:"uptime_at_query_ms"`
	EventClockAtQueryMS     *uint64 `json:"event_clock_at_query_ms"`
	ClockSampleSpanMS       *uint64 `json:"clock_sample_span_ms"`
	ConsoleEventCount       *uint64 `json:"console_event_count"`
	TaskProcessIsPowerShell *bool   `json:"task_process_is_powershell"`
	BootMarker              uint64  `json:"boot_marker"`
	ClockStable             bool    `json:"clock_stable"`
	LogEnabled              bool    `json:"log_enabled"`
	QueryComplete           bool    `json:"query_complete"`
	TaskStartMS             *uint64 `json:"task_start_ms"`
	ProcessCreatedMS        *uint64 `json:"process_created_ms"`
	ActionStartMS           *uint64 `json:"action_start_ms"`
	ShellStartMS            *uint64 `json:"shell_start_ms"`
	ShellReadyMS            *uint64 `json:"shell_ready_ms"`
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
	for _, v := range []*uint64{r.TaskStartMS, r.ProcessCreatedMS, r.ActionStartMS, r.ShellStartMS, r.ShellReadyMS, r.UptimeAtQueryMS, r.EventClockAtQueryMS, r.ClockSampleSpanMS} {
		if v != nil && (*v > 600000 || !r.ClockStable) {
			return r, errors.New("invalid boot event offset or changed clock")
		}
	}
	if (r.UptimeAtQueryMS != nil && *r.UptimeAtQueryMS == 0) || (r.UptimeAtQueryMS == nil) != (r.EventClockAtQueryMS == nil) || (r.UptimeAtQueryMS == nil) != (r.ClockSampleSpanMS == nil) || (r.ClockSampleSpanMS != nil && *r.ClockSampleSpanMS > 20) || (r.ConsoleEventCount != nil && *r.ConsoleEventCount > 128) {
		return r, errors.New("invalid bounded clock calibration or event count")
	}
	return r, nil
}

func bootEventCommand(script string) string {
	// Only embedded source is encoded. No configuration or guest-supplied value
	// is interpolated into the remote command.
	return "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encodedPowerShell(strings.ReplaceAll(bootEventsCommon+script, "\r\n", "\n"))
}

func joinBootEvents(task, shell, clock bootEventSnapshot) *BootEvents {
	r := &BootEvents{BootMatched: task.BootMarker != 0 && task.BootMarker == shell.BootMarker && task.BootMarker == clock.BootMarker, TaskLogEnabled: task.LogEnabled, TaskQueryComplete: task.QueryComplete, ShellLogEnabled: shell.LogEnabled, ShellQueryComplete: shell.QueryComplete}
	r.ClockStable = r.BootMatched && task.ClockStable && shell.ClockStable && clock.ClockStable
	if r.ClockStable {
		r.ConsoleEventCount = clock.ConsoleEventCount
		r.TaskProcessIsPowerShell = clock.TaskProcessIsPowerShell
		r.UptimeAtQueryMS = clock.UptimeAtQueryMS
		r.EventClockAtQueryMS = clock.EventClockAtQueryMS
		r.ClockSampleSpanMS = clock.ClockSampleSpanMS
		r.TaskStartMS = task.TaskStartMS
		r.ProcessCreatedMS = task.ProcessCreatedMS
		r.ActionStartMS = task.ActionStartMS
		r.ShellStartMS = shell.ShellStartMS
		r.ShellReadyMS = shell.ShellReadyMS
	}
	return r
}

func (a *native) collectBootEvents(ctx context.Context, client *ssh.Client, c Config, runtimeID string) (*BootEvents, error) {
	traceCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var snapshots [3]bootEventSnapshot
	for i, script := range []string{bootEventsTask, bootEventsShell, bootEventsClock} {
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
	return joinBootEvents(snapshots[0], snapshots[1], snapshots[2]), nil
}

// This fixed command runs only inside a verified, authenticated image-build guest,
// after desktop validation and before normal sanitation/acknowledged shutdown.
const enableTaskEventsScript = `$ErrorActionPreference='Stop'
& 'C:\Windows\System32\wevtutil.exe' @('sl','Microsoft-Windows-TaskScheduler/Operational','/e:true') *> $null
if($LASTEXITCODE -or !(Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction Stop).IsEnabled){exit 1}
[Console]::Out.Write('task-events-enabled')`

func enableBootEventLogs(ctx context.Context, client *ssh.Client) error {
	command := "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encodedPowerShell(enableTaskEventsScript)
	out, _, err := runGuestSSH(ctx, client, command, nil)
	defer clear(out)
	if err != nil || string(out) != "task-events-enabled" {
		return errors.New("diagnostic guest task event logging was not acknowledged")
	}
	return nil
}
