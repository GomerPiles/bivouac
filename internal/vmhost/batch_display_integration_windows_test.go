//go:build windows && integration

package vmhost

import (
	"encoding/json"
	"flag"
	"github.com/GomerPiles/bivouac/internal/winguest"
	"testing"
)

func TestLabDisplayFlagRemoved(t *testing.T) {
	if flag.Lookup("lab.display") != nil {
		t.Fatal("removed lab flag registered")
	}
}

func TestLabDisplayReportGate(t *testing.T) {
	good := render{GuestReady: true, DesktopReady: true, HardwareD3D11: true, Presented: true, PixelReadback: true, Stage: 7, HardwareAdapters: 1, CredentialRotated: true,
		Topology: winguest.Topology{TopologyValid: true, ActiveDisplays: 1, PrimaryDisplays: 1, PrimaryWidth: 1024, PrimaryHeight: 768, VirtualEqualsPrimary: true, AdapterKind: 1, HyperVEnabled: true, HyperVStarted: true, ProbeForeground: true, ProbeOnPrimary: true, ProbeInput: true}}
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
