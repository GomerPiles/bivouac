//go:build windows

package hcsspike

import (
	"strings"
	"testing"
)

func TestValidationProgressRetainsOnlyAllowedCompletePhases(t *testing.T) {
	var p validationProgress
	for _, part := range []string{"private guest diagnostics\nBIVOUAC_HCS_", "STEP:20\r\n", "BIVOUAC_HCS_STEP:999\n", strings.Repeat("x", 64) + "BIVOUAC_HCS_STEP:25\n", "BIVOUAC_HCS_STEP:4294967296\n", "BIVOUAC_HCS_STEP:22"} {
		if n, err := p.Write([]byte(part)); err != nil || n != len(part) {
			t.Fatal("stderr drain failed")
		}
	}
	if p.step != 20 {
		t.Fatal("noise, unbounded or incomplete stderr changed phase")
	}
	if _, err := p.Write([]byte("\n")); err != nil || p.step != 22 {
		t.Fatal("complete phase missing")
	}
	if p.length != 0 || p.overflow {
		t.Fatal("completed line was retained")
	}
}
