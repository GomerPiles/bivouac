//go:build windows && integration

package vmhost

import (
	"encoding/json"
	"flag"
	"testing"

	"github.com/GomerPiles/bivouac/internal/winguest"
)

func TestLabDisplayFlag(t *testing.T) {
	for _, value := range []string{"vdd", "synthetic", "invalid"} {
		fs := flag.NewFlagSet("lab", flag.ContinueOnError)
		mode := labDisplayFlag(fs)
		if *mode != "vdd" {
			t.Fatal("default changed")
		}
		if err := fs.Parse([]string{"-lab.display=" + value}); err != nil {
			t.Fatal(err)
		}
		parsed, err := winguest.ParseDisplayMode(*mode)
		if (err == nil) != (value != "invalid") || (err == nil && string(parsed) != value) {
			t.Fatal("lab mode parsing")
		}
	}
}

func TestLabDisplayReportGate(t *testing.T) {
	good := render{GuestReady: true, DesktopReady: true, HardwareD3D11: true, Presented: true, PixelReadback: true, Stage: 7, HardwareAdapters: 1, CredentialRotated: true,
		Topology: winguest.Topology{TopologyValid: true, ActiveDisplays: 1, PrimaryDisplays: 1, PrimaryWidth: 1024, PrimaryHeight: 768, VirtualEqualsPrimary: true, AdapterKind: 2, ProbeForeground: true, ProbeOnPrimary: true, ProbeInput: true}}
	if !good.ok(winguest.DisplayVDD) {
		t.Fatal("single VDD accepted image refused")
	}
	for _, change := range []func(*render){func(r *render) { r.ActiveDisplays = 3 }, func(r *render) { r.PrimaryDisplays = 0 }, func(r *render) { r.ProbeForeground = false }, func(r *render) { r.ProbeOnPrimary = false }, func(r *render) { r.ProbeInput = false }, func(r *render) { r.HardwareD3D11 = false }} {
		bad := good
		change(&bad)
		if bad.ok(winguest.DisplayVDD) {
			t.Fatal("failed report accepted")
		}
	}
	good.SecurityWindow = true
	good.SecurityOnPrimary = false
	if !good.ok(winguest.DisplayVDD) {
		t.Fatal("security facts gated lab")
	}
	b, err := json.Marshal(good)
	if err != nil || len(b) > 8192 {
		t.Fatal("report bound")
	}
	var decoded render
	if json.Unmarshal(b, &decoded) != nil || !decoded.ok(winguest.DisplayVDD) || decoded.SecurityOnPrimary || !decoded.SecurityWindow {
		t.Fatal("report facts lost")
	}
	if json.Unmarshal([]byte(`{"active_display_count":"guest-private-output"}`), &decoded) == nil {
		t.Fatal("text topology accepted")
	}
	good.AdapterKind = 1
	good.HyperVEnabled = true
	good.HyperVStarted = true
	if !good.ok(winguest.DisplayVDD) || !good.ok(winguest.DisplaySynthetic) {
		t.Fatal("valid synthetic report refused")
	}
	for name, change := range map[string]func(*render){
		"VDD primary":    func(r *render) { r.AdapterKind = 2 },
		"VDD node":       func(r *render) { r.VDDNodes = 1 },
		"video disabled": func(r *render) { r.HyperVEnabled = false },
		"video stopped":  func(r *render) { r.HyperVStarted = false },
	} {
		t.Run(name, func(t *testing.T) {
			bad := good
			change(&bad)
			if !bad.ok(winguest.DisplayVDD) || bad.ok(winguest.DisplaySynthetic) {
				t.Fatal("synthetic topology gate did not follow selected mode")
			}
		})
	}
	good.ProbeInput = false
	if good.ok(winguest.DisplayVDD) || good.ok(winguest.DisplaySynthetic) {
		t.Fatal("mode-specific topology bypassed lab input gate")
	}
}
