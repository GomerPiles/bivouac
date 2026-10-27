//go:build windows

package main

import "testing"

func TestNativeBindingRequiresLiveMarkerAndNativeTuple(t *testing.T) {
	record := labRecord{Name: "bivouac-sandbox-11111111-2222-4333-8444-555555555555", ID: "11111111-2222-4333-8444-555555555555", Phase: "started", Boot: "66666666-7777-4888-8999-aaaaaaaaaaaa"}
	guest := record
	binding := nativeBinding{NativeID: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", Probe: nativeFacts{HCS: true, Running: true, IDMatches: true, VM: true, Runtime: true, Agent: true, Session: sessionFacts{Session: 1, User: true, Elevated: true, Active: true, Desktop: true}, OwnerHash: sandboxOwnerHash(), RuntimeID: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", Identity: &guest}}
	if !binding.matches(record) {
		t.Fatal("corroborated binding refused")
	}
	for _, change := range []func(*nativeBinding){
		func(b *nativeBinding) { b.NativeID = "unrecorded" },
		func(b *nativeBinding) { b.Probe.HCS = false },
		func(b *nativeBinding) { b.Probe.Running = false },
		func(b *nativeBinding) { b.Probe.IDMatches = false },
		func(b *nativeBinding) { b.Probe.VM = false },
		func(b *nativeBinding) { b.Probe.Runtime = false },
		func(b *nativeBinding) { b.Probe.RuntimeID = "" },
		func(b *nativeBinding) { b.Probe.Agent = false },
		func(b *nativeBinding) { b.Probe.Session.User = false },
		func(b *nativeBinding) { b.Probe.OwnerHash = "foreign" },
		func(b *nativeBinding) { b.Probe.Identity = nil },
		func(b *nativeBinding) { b.Probe.Identity.ID = b.NativeID },
		func(b *nativeBinding) { b.Probe.Identity.Name = "bivouac-sandbox-foreign" },
		func(b *nativeBinding) { b.Probe.Identity.Boot = b.NativeID },
		func(b *nativeBinding) { b.Probe.Identity.Phase = "stopped" },
	} {
		bad := binding
		identity := guest
		bad.Probe.Identity = &identity
		change(&bad)
		if bad.matches(record) {
			t.Fatal("unproven native binding accepted")
		}
	}
	for _, report := range []correlationReport{{}, {Candidates: 1}, {Candidates: 17, Matches: []nativeBinding{binding}}, {Candidates: 2, Matches: []nativeBinding{binding, binding}}} {
		if _, err := report.binding(record); err == nil {
			t.Fatal("ambiguous or absent binding accepted")
		}
	}
	proof, err := (correlationReport{Candidates: 2, Matches: []nativeBinding{binding}}).binding(record)
	if err != nil || !proof.valid() {
		t.Fatal("unique matching marker refused")
	}
	// Reused native IDs cannot authorize a later boot, even if all native
	// properties and the CLI ID are otherwise identical.
	reused := record
	reused.Boot = binding.NativeID
	if binding.matches(reused) {
		t.Fatal("native reuse accepted a stale boot marker")
	}
}

func TestRecordedNativeIdentityRefusesMalformedState(t *testing.T) {
	record := labRecord{Name: "bivouac-sandbox-11111111-2222-4333-8444-555555555555", ID: "11111111-2222-4333-8444-555555555555", Phase: "started", Boot: "66666666-7777-4888-8999-aaaaaaaaaaaa", Native: &nativeIdentity{ID: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", RuntimeID: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", OwnerHash: sandboxOwnerHash()}}
	if !record.valid() {
		t.Fatal("native record refused")
	}
	record.Native.RuntimeID = "not-a-runtime"
	if record.valid() {
		t.Fatal("malformed native state accepted")
	}
}
