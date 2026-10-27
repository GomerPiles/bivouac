//go:build windows

package winrunner

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLabFilteredTokenRunsUnprivileged(t *testing.T) {
	// The filtered proof requires a deny-only Administrators group, which a
	// non-administrator's token does not carry at all.
	self, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		t.Fatal(err)
	}
	admin := false
	for _, g := range self.AllGroups() {
		admin = admin || g.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
	}
	if !admin {
		t.Skip("account is not an administrator")
	}
	token, err := labFilteredToken()
	if err != nil {
		t.Fatal("filtered token unavailable")
	}
	defer func() { _ = token.Close() }()
	if !labTokenFiltered(token) {
		t.Fatal("derived token is not this account's filtered token")
	}
	if labTokenFiltered(windows.Token(0)) {
		t.Fatal("invalid token accepted as filtered")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	code, err := runWithToken(t.Context(), token, filepath.Join(system, "hostname.exe"), nil)
	if err != nil || code != 0 {
		t.Fatal("filtered process did not run", err, code)
	}
	code, err = runWithToken(t.Context(), token, filepath.Join(system, "schtasks.exe"), []string{"/Query", "/TN", `\bivouac-lab-no-such-task`})
	if err != nil || code == 0 {
		t.Fatal("exit status not propagated", err, code)
	}
}

func TestLabRunnerRunFactsRequireEveryProof(t *testing.T) {
	good := LabRunnerRunFacts{FilteredToken: true, AgentQueryAccepted: true, RunnerQueryRefused: true, FilteredRefused: true, ElevatedAccepted: true}
	if !good.Valid() {
		t.Fatal("complete proof refused")
	}
	// The agent-run diagnostic never gates.
	diagnostic := good
	diagnostic.AgentRunAccepted = true
	if !diagnostic.Valid() {
		t.Fatal("diagnostic changed the gate")
	}
	for _, clear := range []func(*LabRunnerRunFacts){
		func(f *LabRunnerRunFacts) { f.FilteredToken = false },
		func(f *LabRunnerRunFacts) { f.AgentQueryAccepted = false },
		func(f *LabRunnerRunFacts) { f.RunnerQueryRefused = false },
		func(f *LabRunnerRunFacts) { f.FilteredRefused = false },
		func(f *LabRunnerRunFacts) { f.ElevatedAccepted = false },
	} {
		bad := good
		clear(&bad)
		if bad.Valid() {
			t.Fatal("incomplete proof accepted")
		}
	}
}
