//go:build windows

package main

import (
	"testing"

	"github.com/GomerPiles/bivouac/internal/wintools"
)

func TestToolFactsRequireExactBootRecipeAndFunctionalProof(t *testing.T) {
	id := "11111111-2222-4333-8444-555555555555"
	record := labRecord{Name: "bivouac-sandbox-" + id, ID: id, Phase: "started", Boot: "66666666-7777-4888-8999-aaaaaaaaaaaa"}
	recipes, err := wintools.Resolve([]string{"cmake", "ninja"})
	if err != nil {
		t.Fatal(err)
	}
	fixture := func() toolFacts {
		f := toolFacts{Identity: record, Build: true}
		for _, r := range recipes {
			f.Tools = append(f.Tools, toolFact{Name: r.Name, Version: r.Version, SHA256: r.SHA256, Variant: r.Variant, Verified: true})
		}
		return f
	}
	if !fixture().valid(record, recipes) {
		t.Fatal("matching tool proof refused")
	}
	for _, change := range []func(*toolFacts){
		func(f *toolFacts) { f.Identity.Boot = id },
		func(f *toolFacts) { f.Tools[0].SHA256 = "incorrect" },
		func(f *toolFacts) { f.Tools[0].Version = "unreviewed" },
		func(f *toolFacts) { f.Tools[0].Variant = "unreviewed" },
		func(f *toolFacts) { f.Tools[0].Verified = false },
		func(f *toolFacts) { f.Build = false },
		func(f *toolFacts) { f.Tools = f.Tools[:1] },
	} {
		f := fixture()
		change(&f)
		if f.valid(record, recipes) {
			t.Fatal("contradictory tool proof accepted")
		}
	}
}

func TestMSVCReportCannotPromoteIncompleteOrForeignLayout(t *testing.T) {
	id := "11111111-2222-4333-8444-555555555555"
	record := labRecord{Name: "bivouac-sandbox-" + id, ID: id, Phase: "started", Boot: "66666666-7777-4888-8999-aaaaaaaaaaaa"}
	fixture := func() msvcLayoutFacts {
		return msvcLayoutFacts{Identity: record, Stage: 4, Complete: true, BootstrapVerified: true, Files: 10, Bytes: 1024, Errors: map[string]bool{"file_missing": false, "file_load": false, "io": false, "access_denied": false, "not_supported": false, "web": false, "invalid_operation": false}}
	}
	if !fixture().valid(record) {
		t.Fatal("bounded layout result refused")
	}
	for _, change := range []func(*msvcLayoutFacts){
		func(f *msvcLayoutFacts) { f.Identity.Boot = id },
		func(f *msvcLayoutFacts) { f.Files = 0 },
		func(f *msvcLayoutFacts) { f.Failed = true },
		func(f *msvcLayoutFacts) { f.ExitCode = 3010 },
		func(f *msvcLayoutFacts) { f.BootstrapVerified = false },
		func(f *msvcLayoutFacts) { f.Stage = 2 },
		func(f *msvcLayoutFacts) { f.Bytes = 21 << 30 },
		func(f *msvcLayoutFacts) { f.Errors["arbitrary_log"] = true },
		func(f *msvcLayoutFacts) { f.Frames = []string{"https://example.invalid/diagnostic"} },
	} {
		f := fixture()
		change(&f)
		if f.valid(record) {
			t.Fatal("contradictory layout result accepted")
		}
	}
}
