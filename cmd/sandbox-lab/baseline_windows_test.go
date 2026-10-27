//go:build windows

package main

import "testing"

func TestBaselineRequiresPinnedGuestAndFixedVocabulary(t *testing.T) {
	record := labRecord{Name: "bivouac-sandbox-11111111-2222-4333-8444-555555555555", ID: "11111111-2222-4333-8444-555555555555", Phase: "started", Boot: "66666666-7777-4888-8999-aaaaaaaaaaaa"}
	facts := baselineFacts{Identity: record, WindowsBuild: 26100, Services: map[string]struct {
		Present bool `json:"present"`
		Running bool `json:"running"`
	}{}, Tools: map[string]bool{}}
	for _, name := range []string{"WinDefend", "WSearch", "wuauserv", "SysMain", "Sense"} {
		facts.Services[name] = struct {
			Present bool `json:"present"`
			Running bool `json:"running"`
		}{}
	}
	for _, name := range []string{"pwsh", "git", "7zip", "cmake", "ninja", "python", "node", "dotnet", "llvm", "runner_node", "msvc", "msbuild", "windows_sdk"} {
		facts.Tools[name] = false
	}
	if !facts.valid(record) {
		t.Fatal("explicit absence was mistaken for an invalid inventory")
	}
	changed := record
	changed.Boot = record.ID
	if facts.valid(changed) {
		t.Fatal("stale guest inventory accepted")
	}
	facts.Tools["arbitrary"] = true
	if facts.valid(record) {
		t.Fatal("unbounded tool names accepted")
	}
	delete(facts.Tools, "arbitrary")
	facts.WindowsSDKVersions = []string{"untrusted-output"}
	if facts.valid(record) {
		t.Fatal("raw tool output accepted as a version")
	}
}
