package main

import (
	"strings"
	"testing"
)

func TestOwnershipRequiresReceiptAndFreshGuestProof(t *testing.T) {
	id := "11111111-2222-4333-8444-555555555555"
	boot := "66666666-7777-4888-8999-aaaaaaaaaaaa"
	request := "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
	r := labRecord{Name: "bivouac-sandbox-" + id, ID: id, Phase: "started", Boot: boot}
	p := ownershipProof{Name: r.Name, ID: id, Boot: boot, Request: request}
	if !r.accepts(p, request) {
		t.Fatal("matching proof refused")
	}
	for _, change := range []func(*labRecord, *ownershipProof){
		func(r *labRecord, _ *ownershipProof) { r.Phase = "planned" },
		func(r *labRecord, _ *ownershipProof) { r.Phase = "stopped" },
		func(r *labRecord, _ *ownershipProof) { r.Name = "personal-sandbox" },
		func(_ *labRecord, p *ownershipProof) { p.ID = boot },
		func(_ *labRecord, p *ownershipProof) { p.Name = "foreign" },
		func(_ *labRecord, p *ownershipProof) { p.Boot = request },
		func(_ *labRecord, p *ownershipProof) { p.Request = boot },
		func(_ *labRecord, p *ownershipProof) { p.Boot = "" },
	} {
		rr, pp := r, p
		change(&rr, &pp)
		if rr.accepts(pp, request) {
			t.Fatal("unproven instance accepted")
		}
	}
}

func TestInventoryFailsClosed(t *testing.T) {
	for _, data := range []string{`{}`, `{"WindowsSandboxEnvironments":null}`, `{"WindowsSandboxEnvironments":[{"Id":"unknown"}]}`, `{"WindowsSandboxEnvironments":[]} trailing`, strings.Repeat(" ", 65537)} {
		if _, err := listed([]byte(data)); err == nil {
			t.Fatal("invalid inventory accepted")
		}
	}
	ids, err := listed([]byte(`{"WindowsSandboxEnvironments":[]}`))
	if err != nil || len(ids) != 0 {
		t.Fatal("empty inventory refused")
	}
	if _, err := listed([]byte(`{"WindowsSandboxEnvironments":[{"Id":"11111111-2222-4333-8444-555555555555"}]}`)); err != nil {
		t.Fatal(err)
	}
}
