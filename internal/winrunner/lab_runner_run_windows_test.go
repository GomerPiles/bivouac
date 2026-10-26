//go:build windows

package winrunner

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLabFilteredTokenRunsUnprivileged(t *testing.T) {
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
	good := LabRunnerRunFacts{FilteredToken: true, FilteredRefused: true, ElevatedAccepted: true}
	if !good.Valid() {
		t.Fatal("complete proof refused")
	}
	for _, bad := range []LabRunnerRunFacts{{FilteredRefused: true, ElevatedAccepted: true}, {FilteredToken: true, ElevatedAccepted: true}, {FilteredToken: true, FilteredRefused: true}} {
		if bad.Valid() {
			t.Fatal("incomplete proof accepted")
		}
	}
}
