//go:build windows && integration

package vmhost

import (
	"encoding/json"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/windesktop"
)

func TestLabDisplayFlagRemoved(t *testing.T) {
	if flag.Lookup("lab.display") != nil {
		t.Fatal("removed lab flag registered")
	}
}

func TestLabAgentReportAndAuthorization(t *testing.T) {
	for _, result := range []map[string]string{nil, {"granted_agent": "connected"}, {"ungranted_agent": "access-denied"}} {
		if !authorizationOK(result) {
			t.Fatal("valid authorization refused")
		}
	}
	for _, result := range []map[string]string{{}, {"granted_agent": "access-denied"}, {"ungranted_agent": "connected"}, {"unknown": "connected"}} {
		if authorizationOK(result) {
			t.Fatal("invalid authorization accepted")
		}
	}
	output := &validationOutput{steps: map[string]int64{}, begun: time.Now()}
	for _, part := range []string{"BIVOUAC_HCS_ST", "EP:1\r\nBIVOUAC_HCS_STEP:4\n", `{"guest_ready":true}`} {
		if _, err := output.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if len(output.steps) != 2 || string(output.pending) != `{"guest_ready":true}` {
		t.Fatal("step framing lost")
	}
	if _, err := output.Write([]byte(strings.Repeat("x", 8193))); err == nil {
		t.Fatal("unbounded validation output")
	}
	data, err := json.Marshal(labRun{Timings: map[string]int64{"agent_reachable": 1}})
	if err != nil || !strings.Contains(string(data), "agent_reachable") || strings.Contains(string(data), "ssh") {
		t.Fatal("legacy lab report")
	}
}

func TestLabDisplayReportGate(t *testing.T) {
	good := render{GuestReady: true, DesktopReady: true, HardwareD3D11: true, Presented: true, PixelReadback: true, Stage: 7, HardwareAdapters: 1, CredentialRotated: true,
		Topology: windesktop.Topology{TopologyValid: true, ActiveDisplays: 1, PrimaryDisplays: 1, PrimaryWidth: 1024, PrimaryHeight: 768, VirtualEqualsPrimary: true, AdapterKind: 1, HyperVEnabled: true, HyperVStarted: true, ProbeForeground: true, ProbeOnPrimary: true, ProbeInput: true}}
	if !good.ok() {
		t.Fatal("valid synthetic report refused")
	}
	for name, change := range map[string]func(*render){
		"multiple displays": func(r *render) { r.ActiveDisplays = 3 }, "no primary": func(r *render) { r.PrimaryDisplays = 0 },
		"foreground": func(r *render) { r.ProbeForeground = false }, "placement": func(r *render) { r.ProbeOnPrimary = false }, "input": func(r *render) { r.ProbeInput = false }, "hardware render": func(r *render) { r.HardwareD3D11 = false },
		"VDD primary": func(r *render) { r.AdapterKind = 2 }, "VDD node": func(r *render) { r.VDDNodes = 1 }, "video disabled": func(r *render) { r.HyperVEnabled = false }, "video stopped": func(r *render) { r.HyperVStarted = false },
	} {
		t.Run(name, func(t *testing.T) {
			bad := good
			change(&bad)
			if bad.ok() {
				t.Fatal("invalid report accepted")
			}
		})
	}
	good.SecurityWindow = true
	good.SecurityOnPrimary = false
	if !good.ok() {
		t.Fatal("security observations gated lab")
	}
	b, err := json.Marshal(good)
	if err != nil || len(b) > 8192 {
		t.Fatal("report bound")
	}
	var decoded render
	if json.Unmarshal(b, &decoded) != nil || !decoded.ok() || decoded.SecurityOnPrimary || !decoded.SecurityWindow {
		t.Fatal("report facts lost")
	}
	if json.Unmarshal([]byte(`{"active_display_count":"guest-private-output"}`), &decoded) == nil {
		t.Fatal("text topology accepted")
	}
}
