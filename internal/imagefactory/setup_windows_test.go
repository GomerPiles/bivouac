//go:build windows

package imagefactory

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "Windows", "Panther", "Unattend")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(dir, "setup-step.json")
}

// Extract only the status writer and redirect its fixed guest path into the
// fixture. Guest setup/specialize scripts are never executed as host scripts.
func fixtureStepWriter(t *testing.T, source string) string {
	t.Helper()
	start := strings.Index(source, "function Write-SetupStep")
	if start < 0 {
		t.Fatal("status writer missing")
	}
	end := strings.Index(source[start:], "\n}\n")
	if end < 0 {
		t.Fatal("status writer end missing")
	}
	return strings.ReplaceAll(source[start:start+end+3], `'C:\Windows\Panther\Unattend\setup-step.json'`, "$fixturePath")
}

func TestSyntheticSpecializeBarrier(t *testing.T) {
	start := strings.Index(guestSetup, " # Do not replace")
	end := strings.Index(guestSetup, " $step=10\n Write-SetupStep")
	if start < 0 || end <= start {
		t.Fatal("specialize guard missing")
	}
	guard := guestSetup[start:end]
	for _, test := range []struct {
		name, status string
		step         uint32
		failed       bool
	}{
		{"completed", `{"step":88,"failed":false}`, 10, false},
		{"failed", `{"step":82,"failed":true}`, 82, true},
		{"interrupted", `{"step":84,"failed":false}`, 84, true},
		{"missing", "", 89, true},
		{"invalid", `{"step":"guest-private-output","failed":false}`, 89, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, path := setupFixture(t)
			if test.status != "" {
				if err := os.WriteFile(path, []byte(test.status), 0600); err != nil {
					t.Fatal(err)
				}
			}
			input, _ := json.Marshal(map[string]string{"path": path})
			script := `$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json;$fixturePath=$data.path;$step=10;$videoDiagnostics=$null
function Join-Path {param($Path,$ChildPath) return $fixturePath}
` + videoFacts + fixtureStepWriter(t, guestSetup) + "\ntry {\n" + guard + "\n$step=10;Write-SetupStep $step $false\n}catch{Write-SetupStep $step $true}\n" + `[Console]::Out.Write([IO.File]::ReadAllText($fixturePath))`
			var status struct {
				Step   uint32
				Failed bool
			}
			out := runTestPS(t, script, input)
			if json.Unmarshal([]byte(out), &status) != nil || status.Step != test.step || status.Failed != test.failed || strings.Contains(out, "guest-private-output") {
				t.Fatal("specialize failure was overwritten or bypassed")
			}
		})
	}
}

func TestSpecializeFailureStep(t *testing.T) {
	_, path := setupFixture(t)
	start := strings.Index(guestSpecialize, "function Write-SetupStep")
	end := strings.Index(guestSpecialize[start:], "\n}\n") + start + 3
	script := "$data=[Console]::In.ReadToEnd()|ConvertFrom-Json;$fixturePath=$data.path\nfunction Get-Service {throw 'fixture failure'}\n" + guestSpecialize[:start] + fixtureStepWriter(t, guestSpecialize) + guestSpecialize[end:]
	file := filepath.Join(t.TempDir(), "fixture-specialize.ps1")
	if err := os.WriteFile(file, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]string{"path": path})
	_, err := executeHost(t.Context(), file, input, false)
	var scriptErr *HostScriptError
	if !errors.As(err, &scriptErr) || scriptErr.Step != 80 {
		t.Fatal("specialize failure exit step")
	}
	b, err := os.ReadFile(path)
	var status struct {
		Step   uint32
		Failed bool
	}
	if err != nil || json.Unmarshal(b, &status) != nil || status.Step != 80 || !status.Failed {
		t.Fatal("specialize failure marker")
	}
}
