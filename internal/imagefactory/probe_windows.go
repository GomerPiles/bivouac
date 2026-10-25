//go:build windows

package imagefactory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

const probeFailureLimit = 2048

type probeFailureReport struct {
	TaskObserved     bool   `json:"task_observed"`
	TaskState        uint32 `json:"task_state"`
	LastResult       uint32 `json:"last_result"`
	ProcessObserved  bool   `json:"process_observed"`
	RenderCount      uint32 `json:"render_count"`
	RenderRunning    bool   `json:"render_running"`
	RenderCPUMS      uint64 `json:"render_cpu_ms"`
	DisplayObserved  bool   `json:"display_observed"`
	PresentDisplays  uint32 `json:"present_display_count"`
	GPUCount         uint32 `json:"gpu_count"`
	GPUObserved      bool   `json:"gpu_observed"`
	GPUProblem       uint32 `json:"gpu_problem_code"`
	GPUDevnode       uint32 `json:"gpu_devnode_status"`
	ExplorerObserved bool   `json:"explorer_observed"`
	ExplorerAge      uint32 `json:"explorer_age_seconds"`
	WaitSeconds      uint32 `json:"wait_seconds"`
	WaitBudget       uint32 `json:"wait_budget_seconds"`
}

// Guest bytes are never formatted, even in decoder errors. Require every field
// exactly once, no nulls, no unknown fields, and exactly one complete object.
func probeFailureShape(b []byte) string {
	if len(b) == 0 || len(b) > probeFailureLimit {
		return ""
	}
	d := json.NewDecoder(bytes.NewReader(b))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return ""
	}
	fields := make(map[string]bool)
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] {
			return ""
		}
		fields[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ""
		}
	}
	schema := reflect.TypeFor[probeFailureReport]()
	if token, err = d.Token(); err != nil || token != json.Delim('}') || len(fields) != schema.NumField() {
		return ""
	}
	for i := range schema.NumField() {
		if !fields[schema.Field(i).Tag.Get("json")] {
			return ""
		}
	}
	if d.Decode(new(json.RawMessage)) != io.EOF {
		return ""
	}
	var r probeFailureReport
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || r.TaskState > 4 || r.RenderCount > 256 || r.PresentDisplays > 32 || r.GPUCount > 32 || r.RenderRunning != (r.RenderCount > 0) || (r.WaitBudget != 50 && r.WaitBudget != 180) {
		return ""
	}
	bit := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	return fmt.Sprintf("task_observed=%d task_state=%d last_result=0x%08x process_observed=%d render_count=%d render_running=%d render_cpu_ms=%d display_observed=%d present_display_count=%d gpu_count=%d gpu_observed=%d gpu_problem_code=%d gpu_devnode_status=%d explorer_observed=%d explorer_age_seconds=%d wait_seconds=%d wait_budget_seconds=%d",
		bit(r.TaskObserved), r.TaskState, r.LastResult, bit(r.ProcessObserved), r.RenderCount, bit(r.RenderRunning), r.RenderCPUMS, bit(r.DisplayObserved), r.PresentDisplays, r.GPUCount, bit(r.GPUObserved), r.GPUProblem, r.GPUDevnode, bit(r.ExplorerObserved), r.ExplorerAge, r.WaitSeconds, r.WaitBudget)
}
