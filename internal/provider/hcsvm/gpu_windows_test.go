//go:build windows

package hcsvm

import (
	"strings"
	"testing"
)

func TestReadinessRefusesSoftwareOrMissingGPUProof(t *testing.T) {
	for _, reply := range []string{`{"hardware_d3d12":false}`, `{}`, `not-json`} {
		t.Run(reply, func(t *testing.T) {
			p, _, f := fixture(t, true)
			defer p.Close()
			f.replies["guest windows gpu"] = reply
			if err := p.Create(t.Context(), spec()); err != nil {
				t.Fatal(err)
			}
			report, err := p.waitReady(t.Context(), spec().Name)
			if err == nil || report.FailureStep != "gpu_proof" {
				t.Fatal("missing hardware proof admitted", report, err)
			}
			for _, call := range f.calls {
				if strings.HasSuffix(call.command, "clock") {
					t.Fatal("readiness continued after GPU refusal")
				}
			}
		})
	}
}
