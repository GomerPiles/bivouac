package windesktop

import "testing"

func TestTopologyGates(t *testing.T) {
	good := Topology{TopologyValid: true, ActiveDisplays: 1, PrimaryDisplays: 1, PrimaryWidth: 1024, PrimaryHeight: 768, VirtualEqualsPrimary: true, AdapterKind: 1, HyperVEnabled: true, HyperVStarted: true, ProbeForeground: true, ProbeOnPrimary: true, ProbeInput: true}
	if !good.LabOK() || !good.SyntheticOK() {
		t.Fatal("valid topology refused")
	}
	for name, change := range map[string]func(*Topology){
		"missing": func(v *Topology) { v.TopologyValid = false }, "multiple": func(v *Topology) { v.ActiveDisplays = 3 }, "no primary": func(v *Topology) { v.PrimaryDisplays = 0 }, "two primary": func(v *Topology) { v.PrimaryDisplays = 2 }, "virtual": func(v *Topology) { v.VirtualEqualsPrimary = false }, "width": func(v *Topology) { v.PrimaryWidth = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := good
			change(&bad)
			if bad.LabOK() || bad.SyntheticOK() {
				t.Fatal("invalid topology accepted")
			}
		})
	}
	for _, change := range []func(*Topology){func(v *Topology) { v.ProbeForeground = false }, func(v *Topology) { v.ProbeOnPrimary = false }, func(v *Topology) { v.ProbeInput = false }} {
		bad := good
		change(&bad)
		if bad.LabOK() || !bad.SyntheticOK() {
			t.Fatal("lab-only gate")
		}
	}
	for _, change := range []func(*Topology){func(v *Topology) { v.VDDNodes = 1 }, func(v *Topology) { v.AdapterKind = 2 }, func(v *Topology) { v.HyperVEnabled = false }, func(v *Topology) { v.HyperVStarted = false }} {
		bad := good
		change(&bad)
		if bad.SyntheticOK() || bad.LabOK() {
			t.Fatal("synthetic topology gate")
		}
	}
	// Windows Security is observational even when both facts are false.
	good.SecurityWindow = true
	good.SecurityOnPrimary = true
	if !good.LabOK() {
		t.Fatal("security observation affected gate")
	}
}
