//go:build windows && integration

package vmhost

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/winrunner"
)

type agentLiveFacts struct {
	LoopbackRefused     bool                         `json:"loopback_refused"`
	Installation        guestagent.InstallationFacts `json:"installation"`
	Probe               winrunner.LabProbeFacts      `json:"probe"`
	RunnerRun           winrunner.LabRunnerRunFacts  `json:"runner_run"`
	GateStage           string                       `json:"gate_stage"`
	TaskRestartSurvived bool                         `json:"task_restart_survived"`
	AgentKillSurvived   bool                         `json:"agent_kill_survived"`
}

func (f agentLiveFacts) valid() bool {
	return f.LoopbackRefused && f.Installation.Valid() && f.Probe.Valid() && f.RunnerRun.Valid() && f.TaskRestartSurvived && f.AgentKillSurvived
}

func labAgentCommand(ctx context.Context, dial guestagent.Dialer, argv []string, result any) error {
	// Definition/ACL inspection includes bounded Task Scheduler queries; the
	// descriptor query alone may take a minute on a fresh guest.
	attempt, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	output := &validationOutput{steps: map[string]int64{}, begun: time.Now()}
	if guestagent.Run(attempt, dial, argv, nil, output) != nil {
		return errors.New("agent live-gate command failed")
	}
	if result != nil && json.Unmarshal(output.pending, result) != nil {
		return errors.New("invalid bounded agent live-gate facts")
	}
	return nil
}

func agentLiveChecks(ctx context.Context, dial guestagent.Dialer) (facts agentLiveFacts, err error) {
	facts.GateStage = "loopback"
	var loopback struct {
		Refused bool `json:"loopback_refused"`
	}
	if err = labAgentCommand(ctx, dial, []string{guestagent.WindowsPath, "guest-agent", "selftest", "loopback"}, &loopback); err != nil {
		return
	}
	facts.LoopbackRefused = loopback.Refused
	if !facts.LoopbackRefused {
		return facts, errors.New("guest loopback was not refused")
	}
	facts.GateStage = "installation"
	if err = labAgentCommand(ctx, dial, []string{guestagent.WindowsPath, "guest-agent", "selftest", "inspect"}, &facts.Installation); err != nil {
		return
	}
	if !facts.Installation.Valid() {
		return facts, errors.New("installed agent task or ACL facts failed")
	}
	command := func(callCtx context.Context, mode string, result any) error {
		return labAgentCommand(callCtx, dial, []string{guestagent.WindowsPath, "guest", "windows", mode}, result)
	}
	var started struct {
		Started bool `json:"started"`
	}
	facts.GateStage = "probe-start"
	if err = command(ctx, "lab-start", &started); err != nil {
		return
	}
	if !started.Started {
		return facts, errors.New("lab probe was not started")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = errors.Join(err, labAgentCommand(cleanup, dial, []string{guestagent.WindowsPath, "guest", "windows", "lab-stop"}, nil))
	}()
	facts.GateStage = "probe-facts"
	if err = waitLabFacts(ctx, func(checkCtx context.Context) bool {
		return command(checkCtx, "lab-status", &facts.Probe) == nil && facts.Probe.Valid()
	}); err != nil {
		return
	}
	baseline := facts.Probe
	// The probe holds the runner task, so neither run below starts anything.
	facts.GateStage = "runner-run"
	if err = command(ctx, "lab-runner-run", &facts.RunnerRun); err != nil {
		return
	}
	if !facts.RunnerRun.Valid() {
		return facts, errors.New("runner task activation is not limited to administrators")
	}
	for _, cycle := range []struct {
		start, result string
		passed        *bool
	}{{"lab-task-cycle", "lab-task-result", &facts.TaskRestartSurvived}, {"lab-agent-cycle", "lab-agent-result", &facts.AgentKillSurvived}} {
		var scheduled struct {
			Scheduled bool   `json:"scheduled"`
			ID        string `json:"id"`
		}
		facts.GateStage = cycle.start
		if err = command(ctx, cycle.start, &scheduled); err != nil {
			return
		}
		if !scheduled.Scheduled || scheduled.ID == "" {
			return facts, errors.New("agent cycle was not scheduled")
		}
		err = waitLabFacts(ctx, func(checkCtx context.Context) bool {
			var result struct {
				Complete  bool   `json:"complete"`
				Restarted bool   `json:"restarted"`
				ID        string `json:"id"`
			}
			if command(checkCtx, cycle.result, &result) != nil || !result.Complete || !result.Restarted || result.ID != scheduled.ID {
				return false
			}
			return command(checkCtx, "lab-status", &facts.Probe) == nil && facts.Probe.Valid() && facts.Probe.SameTree(baseline)
		})
		if err != nil {
			return
		}
		*cycle.passed = true
	}
	if !facts.valid() {
		err = errors.New("agent live gates failed")
	}
	if err == nil {
		facts.GateStage = "complete"
	}
	return
}

func waitLabFacts(ctx context.Context, check func(context.Context) bool) error {
	wait, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for wait.Err() == nil {
		if check(wait) {
			return nil
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-wait.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return errors.New("agent live-gate proof timed out")
}
