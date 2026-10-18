//go:build windows

package hcsspike

import (
	"strings"
	"testing"
	"time"
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

func TestCheckpointTimingIgnoresNoiseDuplicatesAndIncompleteSpans(t *testing.T) {
	current := time.Unix(100, 0)
	p := validationProgress{now: func() time.Time { return current }}
	write := func(s string) {
		t.Helper()
		if _, err := p.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	write("BIVOUAC_HCS_STEP:20\n")
	current = current.Add(2 * time.Second)
	write("untrusted diagnostics\nBIVOUAC_HCS_STEP:20\n")
	current = current.Add(3 * time.Second)
	write("BIVOUAC_HCS_STEP:21\n")
	if p.spanMS(20, 21) != 5000 {
		t.Fatal("duplicate checkpoint reset start")
	}
	if p.spanMS(24, 25) != 0 || p.spanMS(999, 21) != 0 {
		t.Fatal("unobserved or invalid span reported")
	}
	write("BIVOUAC_HCS_STEP:26\n")
	current = current.Add(1500 * time.Millisecond)
	write("BIVOUAC_HCS_STEP:27\n")
	if p.spanMS(26, 27) != 1500 {
		t.Fatal("GPU wait interval missing")
	}
	current = current.Add(-2 * time.Second)
	write("BIVOUAC_HCS_STEP:24\n")
	if p.spanMS(27, 24) != 0 {
		t.Fatal("negative synthetic interval became an unsigned duration")
	}
}
