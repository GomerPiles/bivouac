package sandboxdiscovery

import (
	"github.com/GomerPiles/bivouac/internal/hcs"
	"testing"
)

func TestCandidatesRefuseUnprovenIdentityAndExcludeForeignSystems(t *testing.T) {
	valid := hcs.Properties{ID: "11111111-2222-4333-8444-555555555555", RuntimeID: "66666666-7777-4888-8999-aaaaaaaaaaaa", Owner: "WindowsSandbox", State: hcs.StateRunning, SystemType: hcs.SystemTypeVM}
	for _, test := range []struct {
		name      string
		change    func(*hcs.Properties)
		wantCount int
		wantError bool
	}{
		{"valid", func(*hcs.Properties) {}, 1, false},
		{"foreign", func(p *hcs.Properties) { p.Owner = "other" }, 0, false},
		{"stopped", func(p *hcs.Properties) { p.State = "Stopped" }, 0, false},
		{"container", func(p *hcs.Properties) { p.SystemType = "Container" }, 0, false},
		{"missing ID", func(p *hcs.Properties) { p.ID = "" }, 0, true},
		{"missing runtime", func(p *hcs.Properties) { p.RuntimeID = "" }, 0, true},
		{"null runtime", func(p *hcs.Properties) { p.RuntimeID = "00000000-0000-0000-0000-000000000000" }, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			property := valid
			test.change(&property)
			result, err := candidates([]hcs.Properties{property})
			if (err != nil) != test.wantError || len(result) != test.wantCount {
				t.Fatal("candidate acceptance differs")
			}
		})
	}
	if _, err := candidates([]hcs.Properties{valid, valid}); err == nil {
		t.Fatal("duplicate native route accepted")
	}
	if _, err := candidates(make([]hcs.Properties, 65)); err == nil {
		t.Fatal("oversized inventory accepted")
	}
}
