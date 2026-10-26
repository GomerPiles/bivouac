//go:build windows

package winrunner

import (
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/guestagent"
)

func TestLabJobDiagnosticsDoNotGate(t *testing.T) {
	if jobQueryFact(errors.New("query failed")) != "unknown" {
		t.Fatal("failed job query claimed absence")
	}
	good := LabProbeFacts{Alive: true, GrandchildAlive: true, User: true, Elevated: true, Console: true, Desktop: true, NormalPriority: true, GrandchildNormalPriority: true, PID: 1, Creation: 2, ChildPID: 3, ChildCreation: 4}
	for _, job := range []string{"true", "false", "unknown"} {
		for _, agent := range []string{"true", "false", "unknown"} {
			good.InJob, good.AgentInImmediateJob = job, agent
			if !good.Valid() {
				t.Fatal("diagnostic job fact gated survival")
			}
		}
	}
}

func TestLabJobListNeverInfersAbsenceFromTruncation(t *testing.T) {
	size := uint32(8 + 2*unsafe.Sizeof(uintptr(0)))
	pids := []uintptr{12, 34}
	for _, tc := range []struct {
		assigned, listed, returned, pid uint32
		want                            string
	}{
		{2, 2, size, 12, "true"}, {2, 2, size, 56, "false"}, {3, 2, size, 56, "unknown"},
		{2, 3, size, 56, "unknown"}, {2, 2, 8, 56, "unknown"}, {0, 0, 0, 56, "unknown"},
	} {
		if got := labMembership(tc.assigned, tc.listed, tc.returned, pids, tc.pid); got != tc.want {
			t.Fatal("incomplete job list misclassified", got)
		}
	}
}

func TestLabCyclesRequireMatchingRequestAndNewAgent(t *testing.T) {
	agent := listenerIdentity{PID: 1, Creation: 2, Image: guestagent.WindowsPath}
	replacement := listenerIdentity{PID: 1, Creation: 3, Image: guestagent.WindowsPath}
	request := labCycleRequest{ID: strings.Repeat("a", 32), Agent: agent}
	for _, mode := range []string{"valid", "old agent", "old completion", "wrong agent", "incomplete", "bad request"} {
		r := request
		result := labCycleCompletion{ID: r.ID, Agent: agent, Complete: true}
		parent := replacement
		switch mode {
		case "old agent":
			parent = agent
		case "old completion":
			result.ID = strings.Repeat("b", 32)
		case "wrong agent":
			result.Agent = replacement
		case "incomplete":
			result.Complete = false
		case "bad request":
			r.ID = "invalid"
		}
		complete, restarted := labCycleResult(r, result, parent)
		if (complete && restarted) != (mode == "valid") {
			t.Fatal("stale or unmatched cycle accepted", mode)
		}
	}
}

func TestLabGateRequiresSameProbeAndGrandchild(t *testing.T) {
	good := LabProbeFacts{Alive: true, GrandchildAlive: true, InJob: "unknown", AgentInImmediateJob: "false", User: true, Elevated: true, Console: true, Desktop: true, NormalPriority: true, GrandchildNormalPriority: true, PID: 1, Creation: 2, ChildPID: 3, ChildCreation: 4}
	if !good.Valid() || !good.SameTree(good) {
		t.Fatal("valid lab proof refused")
	}
	for _, mode := range []string{"child gone", "child priority", "wrong user", "filtered token", "wrong session", "wrong desktop", "new probe", "new child"} {
		bad := good
		switch mode {
		case "child gone":
			bad.GrandchildAlive = false
		case "child priority":
			bad.GrandchildNormalPriority = false
		case "wrong user":
			bad.User = false
		case "filtered token":
			bad.Elevated = false
		case "wrong session":
			bad.Console = false
		case "wrong desktop":
			bad.Desktop = false
		case "new probe":
			bad.Creation++
		case "new child":
			bad.ChildCreation++
		}
		if bad.Valid() && bad.SameTree(good) {
			t.Fatal("unsafe lab gate admitted", mode)
		}
	}
}
