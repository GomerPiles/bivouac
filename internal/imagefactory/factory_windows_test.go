//go:build windows

package imagefactory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/hcs"
	"github.com/GomerPiles/bivouac/internal/perf"
	"golang.org/x/sys/windows"
)

func TestProtectedConfigRejectedBeforeOpen(t *testing.T) {
	called := false
	_, err := loadConfig(`D:\Protected\factory.json`, func(string) error { called = true; return errors.New("unprotected") })
	if !called || err == nil || !strings.Contains(err.Error(), "administrator-protected") {
		t.Fatal("protected config rejection missing")
	}
}
func TestGrantsNeverTargetInput(t *testing.T) {
	workspace := `D:\Images\.builds\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
	var targets []string
	grant := func(path string) error { targets = append(targets, path); return nil }
	for _, path := range []string{`D:\Templates\disk.vhdx`, `D:\Templates`, workspace + `-other\disk.vhdx`, workspace + `\..\..\..\Templates\disk.vhdx`, `C:\Windows\System32\DriverStore\FileRepository\display`} {
		if grantPath(workspace, path, grant) == nil {
			t.Fatal("input grant accepted")
		}
	}
	for _, path := range []string{workspace + `\source.vhdx`, workspace + `\disk.vhdx`} {
		if err := grantPath(workspace, path, grant); err != nil {
			t.Fatal(err)
		}
	}
	if len(targets) != 2 {
		t.Fatal("input reached native grant seam")
	}
	for _, source := range []string{testConfig().Source, filepath.Dir(testConfig().Source)} {
		if mutateOwnedPath(workspace, source, func(string) error { t.Fatal("source reached ACL seam"); return nil }) == nil {
			t.Fatal("source ACL change accepted")
		}
	}
}
func TestSetupMediaGeneration(t *testing.T) {
	c := testConfig()
	r := &record{BuildID: strings.Repeat("a", 32), Name: "bivouac-aaaaaaa", Workspace: t.TempDir(), Manifest: Manifest{Assets: map[string]string{}}}
	var phases []string
	var copied []string
	var answer string
	copyFile := func(_ context.Context, _, dest, pin string, limit int64) (int64, string, error) {
		if limit <= 0 {
			t.Fatal("invalid copy limit")
		}
		copied = append(copied, filepath.Base(dest))
		return 1, pin, os.WriteFile(dest, []byte("public-asset"), 0600)
	}
	run := func(_ context.Context, script string, input any, output bool) ([]byte, error) {
		if output {
			t.Fatal("private output enabled")
		}
		data := input.(map[string]string)
		if data["agent"] != filepath.Join(r.Workspace, "agent.exe") || !pin(data["agent_sha256"]) || data["driver_plan"] != "[]" {
			t.Fatal("agent staging plan missing")
		}
		if data["disk"] != r.disk() || data["instance_id"] != r.BuildID || data["destination"] != filepath.Join(r.Workspace, "setup-private", "setup.iso") {
			t.Fatal("wrong owned setup paths")
		}
		switch script {
		case makeISO:
			phases = append(phases, "iso")
			answer = data["unattend"]
		case offlinePayload + stageSetup:
			phases = append(phases, "answer")
			if answer != data["unattend"] {
				t.Fatal("answer file differs from ISO")
			}
		default:
			t.Fatal("unexpected script")
		}
		if !strings.Contains(data["specialize"], "EnableFirstLogonAnimation") {
			t.Fatal("specialize missing")
		}
		return nil, nil
	}
	if err := prepareMediaWith(context.Background(), c, r, func(p string) error { return os.Mkdir(p, 0700) }, copyFile, run); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(phases, []string{"iso", "answer"}) || len(copied) != len(c.SetupAssets)+2 {
		t.Fatal("media preparation order")
	}
	if !pin(r.Manifest.AgentSHA256) || r.Manifest.WindowsContract != guestagent.WindowsContract {
		t.Fatal("agent manifest pin missing")
	}
	for name, script := range mediaScripts() {
		b, err := os.ReadFile(filepath.Join(r.Workspace, "setup-assets", name))
		if err != nil || string(b) != script {
			t.Fatal("public setup media missing")
		}
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "unattend") || strings.Contains(string(b), "Bv!") {
		t.Fatal("private setup persisted to record")
	}
}

// Parse all scripts, including offline staging helpers, without executing any
// of their mount, service, guest or HCS operations.
func TestPowerShellSyntax(t *testing.T) {
	script := `$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json;foreach($text in $data){$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors);if($errors.Count){exit 1}};[Console]::Out.Write('parsed')`
	texts := []string{makeISO, runnerExtract, guestVideo, videoFacts, videoFacts + guestVideo + guestSetup, guestSetup, stageSetup, guestSpecialize, guestValidate, imageSanitize, autologonSecret, inspectDisk, detachDisk, runnerCheck, offlineFiles, offlinePayload, guestBootstrap}
	texts = append(texts, guestVideo+guestSpecialize+disableFirstLogonAnimation)
	b, _ := json.Marshal(texts)
	if got := runTestPS(t, script, b); got != "parsed" {
		t.Fatal("scripts did not parse")
	}
	pwsh, err := exec.LookPath("pwsh.exe")
	if err != nil {
		t.Fatal("PowerShell 7 parser unavailable")
	}
	path := filepath.Join(t.TempDir(), "parse.ps1")
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", path)
	cmd.Stdin = strings.NewReader(string(b))
	if output, err := cmd.Output(); err != nil || string(output) != "parsed" {
		t.Fatal("PowerShell 7 parsing failed")
	}
}
func runTestPS(t *testing.T, script string, stdin []byte) string {
	t.Helper()
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.ps1")
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	cmd.Env = hostPowerShellEnvironment(system)
	cmd.Stdin = strings.NewReader(string(stdin))
	b, err := cmd.Output()
	if err != nil {
		t.Fatal("isolated PowerShell check failed")
	}
	return string(b)
}
func TestExistingRunnerDirectory(t *testing.T) {
	for _, name := range []string{"missing", "clean", "empty residue", "configured", "credential wildcard", "work", "diag", "incomplete"} {
		t.Run(name, func(t *testing.T) {
			runner := filepath.Join(t.TempDir(), "runner")
			if name != "missing" {
				if err := os.MkdirAll(filepath.Join(runner, "bin"), 0700); err != nil {
					t.Fatal(err)
				}
				for _, file := range []string{"bin/Runner.Listener.exe", "config.cmd", "run.cmd"} {
					if err := os.WriteFile(filepath.Join(runner, file), []byte("public-placeholder"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			switch name {
			case "empty residue":
				for _, dir := range []string{"_work", "_diag"} {
					if err := os.Mkdir(filepath.Join(runner, dir), 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "configured":
				if err := os.WriteFile(filepath.Join(runner, ".runner"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "credential wildcard":
				if err := os.WriteFile(filepath.Join(runner, ".credentials_future"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "work", "diag":
				dir := "_" + name
				if err := os.Mkdir(filepath.Join(runner, dir), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(runner, dir, "residue"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "incomplete":
				if err := os.Remove(filepath.Join(runner, "config.cmd")); err != nil {
					t.Fatal(err)
				}
			}
			script := runnerCheck + `;try{$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;if(Assert-CleanRunner $d.path){[Console]::Out.Write('clean')}else{[Console]::Out.Write('missing')}}catch{[Console]::Out.Write('rejected')}`
			b, _ := json.Marshal(map[string]string{"path": runner})
			got := runTestPS(t, script, b)
			want := "rejected"
			if name == "missing" {
				want = "missing"
			}
			if name == "clean" || name == "empty residue" {
				want = "clean"
			}
			if got != want {
				t.Fatalf("runner result %q, want %q", got, want)
			}
		})
	}
}
func TestNativeDocumentAndOwnership(t *testing.T) {
	c := testConfig()
	r := &record{BuildID: strings.Repeat("a", 32), Name: "bivouac-aaaaaaa", Workspace: `D:\Images\.builds\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, Owner: "bivouac-image:example"}
	doc := document(c, r)
	if len(doc.VirtualMachine.Devices.NetworkAdapters) != 0 || !doc.TerminateOnLastHandleClosed {
		t.Fatal("unsafe native plan")
	}
	if doc.VirtualMachine.Devices.Plan9 != nil || len(doc.VirtualMachine.Devices.HvSocket.HvSocketConfig.ServiceTable) != 1 {
		t.Fatal("unexpected guest service or share")
	}
	if doc.VirtualMachine.Devices.Scsi["Primary"].Attachments["0"].Path == c.Source {
		t.Fatal("source attached directly")
	}
	p := hcs.Properties{ID: r.Name, Owner: r.Owner, SystemType: hcs.SystemTypeVM, RuntimeID: "example", State: hcs.StateRunning}
	if prove(r, p, true) != nil {
		t.Fatal("own guest rejected")
	}
	p.Owner = "foreign"
	if prove(r, p, true) == nil {
		t.Fatal("foreign ownership accepted")
	}
}
func TestResourceAdmission(t *testing.T) {
	s := perf.Sample{TotalBytes: 64 << 30, AvailableBytes: 18 << 30}
	if admission(8192, s) == nil {
		t.Fatal("missing commit counters accepted")
	}
	s.Commit = &perf.CommitSpace{LimitBytes: 64 << 30, UsedBytes: 48 << 30}
	if admission(8192, s) != nil {
		t.Fatal("exact admission reserves rejected")
	}
	s.AvailableBytes--
	if admission(8192, s) == nil {
		t.Fatal("low available memory admitted")
	}
	s.AvailableBytes++
	s.Commit.UsedBytes++
	if admission(8192, s) == nil {
		t.Fatal("low commit headroom admitted")
	}
	s.AvailableBytes = 6 << 30
	s.Commit.UsedBytes = 62 << 30
	if reserveLost(s) {
		t.Fatal("exact running reserves rejected")
	}
	s.AvailableBytes--
	if !reserveLost(s) {
		t.Fatal("low memory did not cancel")
	}
	s.AvailableBytes++
	s.Commit.UsedBytes++
	if !reserveLost(s) {
		t.Fatal("low commit headroom did not cancel")
	}
}
