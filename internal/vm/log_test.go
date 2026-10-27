package vm

import (
	"bytes"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/rootnet"
)

func TestHelperLogIsBoundedWithoutFailingVM(t *testing.T) {
	var out bytes.Buffer
	log := &cappedLog{out: &out, left: 8}
	for range 100 {
		if n, err := log.Write([]byte("numeric status")); err != nil || n != 14 {
			t.Fatal("log cap failed caller")
		}
	}
	if out.Len() != 8 {
		t.Fatal("launch log exceeded cap")
	}
}

func TestTerminalLogSurvivesExhaustion(t *testing.T) {
	var out bytes.Buffer
	log := &cappedLog{out: &out, left: 8, reserved: 32}
	_, _ = log.Write(bytes.Repeat([]byte("x"), 100))
	log.terminal([]byte("network lost; guest retired\n"))
	if !bytes.Contains(out.Bytes(), []byte("\nnetwork lost; guest retired\n")) || out.Len() > 40 {
		t.Fatal("terminal status missing or cap exceeded")
	}
}

func TestCounterReportsOnlyChangesAtMostEachMinute(t *testing.T) {
	var state counterLogState
	now := time.Now()
	first := rootnet.Snapshot{Frames: 1}
	if !state.due(now, first) || state.due(now.Add(time.Minute), first) {
		t.Fatal("unchanged counters repeated")
	}
	second := rootnet.Snapshot{Frames: 2}
	if state.due(now.Add(10*time.Second), second) || !state.due(now.Add(time.Minute), second) {
		t.Fatal("rate limit lost pending change")
	}
}
