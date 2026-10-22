//go:build windows

package imagefactory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func videoFixture() *SetupVideoStatus {
	snapshot := &SetupVideoSnapshot{NodeCount: 2, Nodes: []SetupVideoNode{
		{Present: 1, ProblemCode: 22, DevNodeStatus: 25175040, ConfigFlagsPresent: 1, ConfigFlags: 0x80000003, CSConfigFlagsPresent: 1, CSConfigFlags: 5},
		{Present: 0, ProblemCode: 45, ConfigFlagsPresent: 1, ConfigFlags: 2},
	}}
	enable := &SetupVideoEnable{Returned: 1, Attempts: []SetupVideoAttempt{{NodeIndex: 0, FlagsCleared: 1, PnPUtilStarted: 1, PnPUtilExitCode: 3010, Returned: 1}, {NodeIndex: 1, FlagsCleared: 1, PnPUtilStarted: 1, PnPUtilExitCode: 5, FallbackAttempted: 1, FallbackSucceeded: 1, Returned: 1}}}
	return &SetupVideoStatus{SpecializeBefore: snapshot, SpecializeAfter: snapshot, FirstLogon: snapshot, SpecializeEnable: enable, FirstLogonEnable: enable}
}

func TestSetupVideoFacts(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{"all stages", func(map[string]any) {}, true},
		{"text", func(v map[string]any) {
			v["first_logon"].(map[string]any)["nodes"].([]any)[0].(map[string]any)["problem_code"] = "guest-private-output"
		}, false},
		{"negative", func(v map[string]any) {
			v["first_logon"].(map[string]any)["nodes"].([]any)[0].(map[string]any)["config_flags"] = -1
		}, false},
		{"overflow", func(v map[string]any) {
			v["first_logon"].(map[string]any)["nodes"].([]any)[0].(map[string]any)["devnode_status"] = uint64(1) << 32
		}, false},
		{"fraction", func(v map[string]any) {
			v["first_logon"].(map[string]any)["nodes"].([]any)[0].(map[string]any)["problem_code"] = 1.5
		}, false},
		{"count mismatch", func(v map[string]any) { v["first_logon"].(map[string]any)["node_count"] = 1 }, false},
		{"count bound", func(v map[string]any) { v["first_logon"].(map[string]any)["node_count"] = 33 }, false},
		{"present flag", func(v map[string]any) {
			v["first_logon"].(map[string]any)["nodes"].([]any)[0].(map[string]any)["present"] = 2
		}, false},
		{"missing", func(v map[string]any) {
			delete(v["first_logon"].(map[string]any)["nodes"].([]any)[0].(map[string]any), "csconfig_flags_present")
		}, false},
		{"duplicate attempt", func(v map[string]any) {
			v["specialize_enable"].(map[string]any)["attempts"].([]any)[1].(map[string]any)["node_index"] = 0
		}, false},
		{"exit code text", func(v map[string]any) {
			v["specialize_enable"].(map[string]any)["attempts"].([]any)[0].(map[string]any)["pnputil_exit_code"] = "5"
		}, false},
		{"attempt bound", func(v map[string]any) {
			e := v["specialize_enable"].(map[string]any)
			a := e["attempts"].([]any)[0]
			attempts := make([]any, 33)
			for i := range attempts {
				attempts[i] = a
			}
			e["attempts"] = attempts
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, _ := json.Marshal(videoFixture())
			var v map[string]any
			if json.Unmarshal(b, &v) != nil {
				t.Fatal("fixture")
			}
			test.mutate(v)
			v["private"] = "guest-private-output"
			status, _ := json.Marshal(map[string]any{"step": 35, "failed": true, "video": v})
			root, path := setupFixture(t)
			if err := os.WriteFile(path, status, 0600); err != nil {
				t.Fatal(err)
			}
			input, _ := json.Marshal(map[string]string{"root": root})
			out := runTestPS(t, videoFacts+offlineFiles+`
$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json;$facts=@{};$valid=$true
try{Read-SetupStep $data.root $facts}catch{$valid=$false}
[Console]::Out.Write((@{valid=$valid;facts=$facts}|ConvertTo-Json -Compress -Depth 8))`, input)
			var report struct {
				Valid bool
				Facts Inspection
			}
			if json.Unmarshal([]byte(out), &report) != nil || report.Valid != test.valid || strings.Contains(out, "guest-private-output") {
				t.Fatal("bounded numeric facts")
			}
			if test.valid {
				r := &record{}
				err := r.setupFailure(&report.Facts)
				got, _ := json.Marshal(r.GuestSetupVideo)
				want, _ := json.Marshal(videoFixture())
				if err == nil || string(got) != string(want) || !strings.Contains(err.Error(), string(want)) {
					t.Fatal("record/error lost snapshots")
				}
			}
		})
	}
	// Worst case remains within the status and host-result bounds.
	v := videoFixture()
	for _, s := range []*SetupVideoSnapshot{v.SpecializeBefore, v.SpecializeAfter, v.FirstLogon} {
		s.NodeCount = 32
		s.Nodes = make([]SetupVideoNode, 32)
		for i := range s.Nodes {
			s.Nodes[i] = SetupVideoNode{1, ^uint32(0), ^uint32(0), 1, ^uint32(0), 1, ^uint32(0)}
		}
	}
	for _, e := range []*SetupVideoEnable{v.SpecializeEnable, v.FirstLogonEnable} {
		e.Attempts = make([]SetupVideoAttempt, 32)
		for i := range e.Attempts {
			e.Attempts[i] = SetupVideoAttempt{uint32(i), 1, 1, ^uint32(0), 1, 1, 1}
		}
	}
	b, _ := json.Marshal(map[string]any{"step": 35, "failed": true, "video": v})
	if len(b) > 32768 {
		t.Fatal("status byte bound")
	}
	if err := (&record{}).setupFailure(&Inspection{GuestSetupStep: 100, GuestSetupVideo: v}); err != nil {
		t.Fatal("successful setup")
	}
}

func TestVideoRegistryBindings(t *testing.T) {
	// Compile the real bindings; exercise only pure bit arithmetic and identity
	// rejection before any registry open. No host registry or PnP mutation.
	out := runTestPS(t, guestVideo+`
Initialize-VideoRegistry
foreach($flags in @([uint32]0,[uint32]1,[uint32]2,[uint32]3,[uint32]::MaxValue)){
 if([BivouacVideoRegistry]::ClearDisabled($flags) -ne ($flags -band [uint32]4294967294)){throw 'bit preservation'}
}
foreach($id in @('..\..\fixture','fixture\..\node','fixture\node\leaf\extra','fixture/node/leaf')){
 $rejected=$false;try{$null=[BivouacVideoRegistry]::Read($id,$true)}catch{$rejected=$true};if(!$rejected){throw 'identity accepted'}
}
[Console]::Out.Write('safe')`, nil)
	if out != "safe" {
		t.Fatal("video bindings")
	}
}

// Mock the registry class, PnP reads, and native executable. Only the helper
// definitions and verification fragment run; no service/install/shutdown code.
const videoMocks = `
$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json
Add-Type -TypeDefinition 'public static class BivouacVideoRegistry { public static int Clears; public static uint[] Read(string id,bool clear){if(clear)Clears++;return new uint[]{1,3,1,5};} }'
$script:retry=0;$script:nativeCalls=0;$script:fallbackCalls=0
function Get-PnpDevice {param($Class,[switch]$PresentOnly)
 if(!$data.absent){[pscustomobject]@{InstanceId='fixture\video\a'}}
 if($data.phantom){[pscustomobject]@{InstanceId='fixture\video\b'}}
 if($data.nodes){[pscustomobject]@{InstanceId='ROOT\APPSANDBOXVDD\fixture'}}
}
function Get-PnpDeviceProperty {param($InstanceId,$KeyName)
 $value=switch($KeyName){
  'DEVPKEY_Device_HardwareIds' {if($InstanceId -like 'fixture*'){'VMBUS\{DA0A7802-0000-0000-0000-000000000000}'}else{'ROOT\APPSANDBOXVDD'}}
  'DEVPKEY_Device_IsPresent' {$InstanceId -notlike '*\b'}
  'DEVPKEY_Device_ProblemCode' {if($InstanceId -like '*\b'){45}elseif($data.recover -and $script:retry){0}else{$data.problem}}
  'DEVPKEY_Device_DevNodeStatus' {if($data.recover -and $script:retry){8}else{$data.flags}}
  default {throw 'fixture property'}
 };[pscustomobject]@{Data=$value}
}
function Invoke-FixturePnp {param($Arguments)
 $Operation=$Arguments[0];$InstanceId=$Arguments[1]
 if($Operation -ne '/enable-device' -or $InstanceId -notlike 'fixture\video\*'){throw 'unexpected enable target'}
 $script:nativeCalls++;$script:retry++;$global:LASTEXITCODE=[int]$data.exit_code
}
function Enable-PnpDevice {param($InstanceId,[switch]$Confirm)
 $script:fallbackCalls++;if($data.fallback_fail){throw 'fixture fallback'}
}
function Get-WindowsDriver {param([switch]$Online,[switch]$All) if($data.packages){[pscustomobject]@{OriginalFileName='D:\Fixture\AppSandboxVDD.inf'}}}
function Test-Path {param($LiteralPath) return $data.drivers}
function Start-Sleep {param($Milliseconds)}
$drivers='fixture-drivers';$videoDiagnostics=@{}
`

func TestSyntheticVerificationAndRetry(t *testing.T) {
	start := strings.Index(guestSetup, " function Get-VDDNodes")
	end := strings.Index(guestSetup, "$step=40;Write-SetupStep")
	if start < 0 || end <= start {
		t.Fatal("verification missing")
	}
	verify := strings.ReplaceAll(guestSetup[start:end], "$budget.Elapsed.TotalSeconds -lt 30", "$budget.Elapsed.TotalSeconds -lt 0")
	helper := strings.ReplaceAll(guestVideo, "& (Join-Path $env:SystemRoot 'System32\\pnputil.exe')", "Invoke-FixturePnp")
	for _, test := range []struct {
		name                 string
		problem, flags, step uint32
		options              map[string]any
		failed               bool
		calls                int
	}{
		{"ready", 0, 8, 38, nil, false, 0},
		{"restart", 14, 256, 35, nil, true, 0},
		{"not started", 0, 0, 35, nil, true, 0},
		{"absent", 0, 0, 35, map[string]any{"absent": true}, true, 0},
		{"phantom", 0, 8, 38, map[string]any{"phantom": true}, false, 0},
		{"nodes", 0, 8, 36, map[string]any{"nodes": true}, true, 0},
		{"packages", 0, 8, 37, map[string]any{"packages": true}, true, 0},
		{"directory", 0, 8, 38, map[string]any{"drivers": true}, true, 0},
		{"retry succeeds", 22, 25175040, 38, map[string]any{"recover": true}, false, 1},
		{"retry reboot", 22, 25175040, 35, map[string]any{"exit_code": 3010}, true, 1},
		{"fallback", 22, 25175040, 38, map[string]any{"exit_code": 5, "recover": true}, false, 1},
		{"fallback fails", 22, 25175040, 35, map[string]any{"exit_code": 5, "fallback_fail": true}, true, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, path := setupFixture(t)
			data := map[string]any{"path": path, "problem": test.problem, "flags": test.flags, "exit_code": 0}
			for k, v := range test.options {
				data[k] = v
			}
			input, _ := json.Marshal(data)
			out := runTestPS(t, videoMocks+helper+"\n$fixturePath=$data.path\n"+fixtureStepWriter(t, guestSetup)+"\ntry{\n"+verify+"\n}catch{$caughtLine=$_.InvocationInfo.ScriptLineNumber;Write-SetupStep $step $true}\n"+`
$status=[IO.File]::ReadAllText($fixturePath)|ConvertFrom-Json
[Console]::Out.Write((@{status=$status;line=$caughtLine;calls=$script:nativeCalls;fallback=$script:fallbackCalls;clears=[BivouacVideoRegistry]::Clears}|ConvertTo-Json -Compress -Depth 8))`, input)
			var result struct {
				Status struct {
					Step   uint32
					Failed bool
					Video  SetupVideoStatus
				}
				Calls, Fallback, Clears int
			}
			if json.Unmarshal([]byte(out), &result) != nil || result.Status.Step != test.step || result.Status.Failed != test.failed || result.Calls != test.calls || result.Clears != test.calls {
				t.Fatalf("verification/retry result: %s", out)
			}
			s := result.Status.Video.FirstLogon
			if s == nil || (test.name == "phantom" && (s.NodeCount != 2 || s.Nodes[1].Present != 0)) {
				t.Fatal("phantom diagnostics missing")
			}
			if test.options["exit_code"] == 5 && result.Fallback != 1 {
				t.Fatal("fallback missing")
			}
		})
	}
}

func TestPrepareUntilExit(t *testing.T) {
	for _, test := range []struct {
		name    string
		exitErr error
	}{{"powered off", nil}, {"observation failed", errors.New("private native output")}} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err := prepareUntilExit(ctx, func(context.Context) error { return test.exitErr }, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
			if err == nil || ctx.Err() != nil || strings.Contains(err.Error(), "private native output") {
				t.Fatal("early exit did not cancel preparation safely")
			}
		})
	}
	for _, prepareErr := range []error{nil, errors.New("fixture preparation failure")} {
		joined := false
		err := prepareUntilExit(t.Context(), func(ctx context.Context) error { <-ctx.Done(); joined = true; return ctx.Err() }, func(context.Context) error { return prepareErr })
		if !joined || !errors.Is(err, prepareErr) {
			t.Fatal("exit watcher not joined")
		}
	}
}

func TestSpecializeVideoSnapshots(t *testing.T) {
	start := strings.Index(guestSpecialize, " $step=85;")
	end := strings.Index(guestSpecialize, " # Windows setup's following boot")
	if start < 0 || end <= start {
		t.Fatal("specialize enable fragment")
	}
	helper := strings.ReplaceAll(guestVideo, "& (Join-Path $env:SystemRoot 'System32\\pnputil.exe')", "Invoke-FixturePnp")
	for _, fail := range []bool{false, true} {
		_, path := setupFixture(t)
		input, _ := json.Marshal(map[string]any{"path": path, "problem": 22, "flags": 25175040, "phantom": true, "exit_code": 5, "fallback_fail": fail, "recover": !fail})
		out := runTestPS(t, videoMocks+helper+"\n$fixturePath=$data.path\n"+fixtureStepWriter(t, guestSpecialize)+"\ntry{\n"+guestSpecialize[start:end]+"\n}catch{Write-SetupStep $step $true}\n"+`
[Console]::Out.Write([IO.File]::ReadAllText($fixturePath))`, input)
		var status struct {
			Step   uint32
			Failed bool
			Video  SetupVideoStatus
		}
		if json.Unmarshal([]byte(out), &status) != nil || status.Step != 85 || status.Failed != fail {
			t.Fatal("specialize result")
		}
		v := status.Video
		if v.SpecializeBefore == nil || v.SpecializeAfter == nil || v.SpecializeEnable == nil || v.SpecializeBefore.NodeCount != 2 || v.SpecializeAfter.NodeCount != 2 || len(v.SpecializeEnable.Attempts) != 2 {
			t.Fatal("specialize snapshots lost")
		}
		if v.SpecializeBefore.Nodes[0].ProblemCode != 22 || v.SpecializeEnable.Returned != (map[bool]uint32{false: 1, true: 0})[fail] {
			t.Fatal("specialize numeric outcome")
		}
		// Exercise the FirstLogon barrier/writer on the actual specialize result.
		if !fail {
			if err := os.WriteFile(path, []byte(strings.Replace(out, `"step":85`, `"step":88`, 1)), 0600); err != nil {
				t.Fatal(err)
			}
			a := strings.Index(guestSetup, " # Do not replace")
			b := strings.Index(guestSetup, " $step=10\n Write-SetupStep")
			data, _ := json.Marshal(map[string]string{"path": path})
			carried := runTestPS(t, `$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json;$fixturePath=$data.path;$videoDiagnostics=@{}
function Join-Path {param($Path,$ChildPath) return $fixturePath}
`+videoFacts+fixtureStepWriter(t, guestSetup)+guestSetup[a:b]+"\nWrite-SetupStep 35 $true\n"+`[Console]::Out.Write([IO.File]::ReadAllText($fixturePath))`, data)
			var first struct{ Video SetupVideoStatus }
			if json.Unmarshal([]byte(carried), &first) != nil || first.Video.SpecializeBefore == nil || first.Video.SpecializeEnable == nil || first.Video.SpecializeEnable.Returned != 1 {
				t.Fatal("FirstLogon lost specialize diagnostics")
			}
		}
	}
}

func TestSetupFailureShutdownAfterStatus(t *testing.T) {
	_, path := setupFixture(t)
	start := strings.Index(guestSetup, "}catch{\n try{Write-SetupStep")
	if start < 0 {
		t.Fatal("failure shutdown fragment")
	}
	fragment := strings.ReplaceAll(guestSetup[start+1:], "& (Join-Path $env:SystemRoot 'System32\\shutdown.exe')", "Invoke-FixtureShutdown")
	// Only the catch fragment runs, with both side effects replaced. A throw in
	// the shutdown mock cannot escape the production catch before exit $step.
	script := `$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json;$fixturePath=$data.path;$step=35;$videoDiagnostics=@{}
function Write-SetupStep {param($Code,$Failed) [IO.File]::WriteAllText($fixturePath,(@{step=$Code;failed=$Failed;order=1}|ConvertTo-Json -Compress))}
function Invoke-FixtureShutdown {param($Arguments)
 if($Arguments.Count -ne 3 -or $Arguments[0] -ne '/s' -or $Arguments[1] -ne '/t' -or $Arguments[2] -ne '0'){throw 'shutdown arguments'}
 $status=[IO.File]::ReadAllText($fixturePath)|ConvertFrom-Json
 if(!$status.failed -or $status.step -ne 35 -or $status.order -ne 1){throw 'shutdown before status'}
 [Console]::Out.Write('BIVOUAC_IMAGE_RESULT' + [Environment]::NewLine + '{"shutdown_after_status":true}' + [Environment]::NewLine)
}


try{throw 'fixture failure'}
` + fragment
	file := path + ".ps1"
	if err := os.WriteFile(file, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]string{"path": path})
	b, err := executeHost(t.Context(), file, input, true)
	var step *HostScriptError
	if !errors.As(err, &step) || step.Step != 35 || !strings.Contains(string(b), `"shutdown_after_status":true`) {
		t.Fatal("failure did not record then shut down")
	}
}

func TestEarlyExitOfflineDiagnostics(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	err := prepareUntilExit(ctx, func(context.Context) error { return nil }, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	if err == nil {
		t.Fatal("early poweroff succeeded")
	}
	r := &record{NativeAttempted: true, BuildID: strings.Repeat("a", 32), Workspace: `D:\Images\.builds\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`}
	absent, inspected, removed := false, false, false
	cleanupErr := cleanupOwned(func() error { return errors.New("already stopped") }, func() error { absent = true; return nil }, func() error {
		if !absent {
			t.Fatal("inspection before native absence")
		}
		facts, e := inspectOwned(ctx, testConfig(), r, true, func(_ context.Context, _ string, input any, _ bool) ([]byte, error) {
			if input.(map[string]string)["mode"] != "setup" {
				t.Fatal("not setup inspection")
			}
			inspected = true
			return json.Marshal(Inspection{GuestSetupStep: 35, GuestSetupFailed: true, GuestSetupVideo: videoFixture()})
		})
		if e != nil {
			return e
		}
		err = errors.Join(err, r.setupFailure(facts))
		return nil
	}, func() error { removed = true; return nil })
	if cleanupErr != nil || !inspected || !removed || !r.GuestSetupFailed || !strings.Contains(err.Error(), `"problem_code":22`) {
		t.Fatal("early exit lost offline setup facts or cleanup")
	}
}
