//go:build windows

package hcsspike

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
	"strings"
	"testing"
	"time"
)

func TestBootEventResponsesRejectUntrustedOffsetsAndFields(t *testing.T) {
	for _, raw := range []string{
		`{"boot_marker":1,"clock_stable":true,"process_created_ms":600001}`,
		`{"boot_marker":1,"clock_stable":true,"process_created_ms":-1}`,
		`{"boot_marker":0,"clock_stable":true}`,
		`{"boot_marker":1,"clock_stable":false,"shell_ready_ms":1}`,
		`{"raw_event":"discarded-private-fixture"}`,
		`{} {}`,
		`{"boot_marker":1,"clock_stable":true,"uptime_at_query_ms":100}`,
		`{"boot_marker":1,"clock_stable":true,"uptime_at_query_ms":100,"event_clock_at_query_ms":100,"clock_sample_span_ms":21}`,
		`{"console_event_count":129}`,
	} {
		_, err := parseBootEventSnapshot([]byte(raw))
		if err == nil || strings.Contains(err.Error(), "discarded-private-fixture") {
			t.Fatal("unsafe event response accepted or leaked")
		}
	}
	offset := uint64(3200)
	a := bootEventSnapshot{BootMarker: 1, ClockStable: true, ProcessCreatedMS: &offset, ShellStartMS: &offset}
	b := a
	for _, mismatch := range []string{"none", "boot", "clock"} {
		b = a
		if mismatch == "boot" {
			b.BootMarker = 2
		}
		if mismatch == "clock" {
			b.ClockStable = false
		}
		r := joinBootEvents(a, b, a)
		if (r.ProcessCreatedMS != nil) != (mismatch == "none") || (r.ShellStartMS != nil) != (mismatch == "none") {
			t.Fatal("cross-boot or stepped-clock interval escaped")
		}
		encoded, _ := json.Marshal(r)
		if strings.Contains(string(encoded), "boot_marker") {
			t.Fatal("absolute boot identity reached public report")
		}
	}
}

const bootEventFixture = `$d=[Console]::In.ReadToEnd()|ConvertFrom-Json
$fixtureEpoch=[DateTime]::SpecifyKind([DateTime]'2000-01-01T00:00:00',[DateTimeKind]::Utc)
function New-FixtureEvent($eventId,$seconds,$process,$record,$xml,$context){
 $entry=[pscustomobject]@{Id=$eventId;TimeCreated=$fixtureEpoch.AddSeconds($seconds);ProcessId=$process;RecordId=$record;Xml=$xml;Properties=@($null,$null,[pscustomobject]@{Value=$context})}
 Add-Member -InputObject $entry -MemberType ScriptMethod -Name ToXml -Value {return $this.Xml}
 return $entry
}
function Get-WinEvent($FilterHashtable,$MaxEvents,$ListLog,$ErrorAction,$ErrorVariable,$LogName,$FilterXPath){
 if($LogName){$FilterHashtable=@{LogName=$LogName}}
 if($ListLog){return [pscustomobject]@{IsEnabled=($d.mode -ne 'disabled')}}
 if($FilterHashtable.LogName -eq 'System'){
  if($FilterHashtable.Id -eq 12){return New-FixtureEvent 12 1 4 10 '<Event><EventData><Data Name="StartTime">2000-01-01T00:00:00Z</Data></EventData></Event>' ''}
  if($d.mode -eq 'clock'){return New-FixtureEvent 1 8 4 11 '<Event/>' ''};return
 }
 if($FilterHashtable.LogName -eq 'Microsoft-Windows-TaskScheduler/Operational'){
  if($d.mode -eq 'overflow'){foreach($n in 1..129){New-FixtureEvent 100 2 10 20 '<Event/>' ''};return}
  if($d.kind -eq 'shell'){if($d.mode -eq 'missing'){return};return New-FixtureEvent 129 3 123 20 '<Event><EventData><Data Name="TaskName">\bivouac-hcs-ssh-hostkeys</Data><Data Name="ProcessID">123</Data></EventData></Event>' ''}
  foreach($id in @(100,129,200)){
   New-FixtureEvent $id $(if($id -eq 100){2}else{3}) 123 20 '<Event><EventData><Data Name="TaskName">\bivouac-hcs-ssh-hostkeys</Data><Data Name="ProcessID">123</Data></EventData></Event>' ''
  }
  New-FixtureEvent 129 0.1 456 19 '<Event><EventData><Data Name="TaskName">\discarded-private-fixture</Data></EventData></Event>' ''
  return
 }
 foreach($id in @(40961,40962)){
  New-FixtureEvent $id $(if($id -eq 40961){3.2}else{5}) 123 40 '<Event/>' ''
  New-FixtureEvent $id 0.1 456 41 '<Event/>' ''
 }
}
$writer=[IO.StringWriter]::new();$previous=[Console]::Out
try{[Console]::SetOut($writer);& ([ScriptBlock]::Create($d.script))}finally{[Console]::SetOut($previous)}
$text=$writer.ToString();if($text.Contains('discarded-private-fixture') -or $text.Contains('AppSandbox')){exit 1}
$r=$text|ConvertFrom-Json
if($r.boot_marker -lt 1){exit 2}
if($d.mode -eq 'clock'){
 if($r.clock_stable -or $null -ne $r.process_created_ms -or $null -ne $r.shell_start_ms){exit 3};exit 0
}
if(!$r.clock_stable){exit 4}
if($d.kind -eq 'task'){
 if($d.mode -eq 'disabled' -or $d.mode -eq 'overflow'){if($r.query_complete -or $null -ne $r.process_created_ms){exit 5}}
 elseif(!$r.query_complete -or $r.task_start_ms -ne 2000 -or $r.process_created_ms -ne 3000 -or $r.action_start_ms -ne 3000){exit 6}
}else{
 if($d.mode -eq 'missing'){if(!$r.log_enabled -or $r.query_complete){exit 10};exit 0}
 if($d.mode -eq 'disabled'){if($r.query_complete -or $null -ne $r.shell_start_ms){exit 8}}
 elseif(!$r.query_complete -or $r.shell_start_ms -ne 3200 -or $r.shell_ready_ms -ne 5000){exit 9}
}
`

func TestBootEventQueriesCorrelateIdentityAndSuppressUnavailableTimes(t *testing.T) {
	for _, part := range []struct{ name, script string }{{"task", bootEventsTask}, {"shell", bootEventsShell}} {
		if len(bootEventCommand(part.script)) > 7800 {
			t.Fatal("fixed event query approaches remote cmd limit")
		}
		for _, mode := range []string{"valid", "clock", "disabled", "overflow", "missing"} {
			if (mode == "overflow" && part.name != "task") || (mode == "missing" && part.name != "shell") {
				continue
			}
			t.Run(part.name+"/"+mode, func(t *testing.T) {
				payload, _ := json.Marshal(map[string]string{"script": bootEventsCommon + part.script, "kind": part.name, "mode": mode})
				if err := runImageFixture(t, bootEventFixture, payload); err != nil {
					t.Fatal("boot event correlation fixture failed", err)
				}
			})
		}
	}
}

type delayedBootEventBackend struct {
	*fakeBackend
	milestone time.Time
}

func (b *delayedBootEventBackend) Probe(ctx context.Context, c Config, id string) (Report, error) {
	r, err := b.fakeBackend.Probe(ctx, c, id)
	r.validatedAt = time.Now()
	b.milestone = r.validatedAt
	time.Sleep(25 * time.Millisecond)
	return r, err
}
func TestReadinessMilestoneExcludesPostReadyDiagnostics(t *testing.T) {
	c, j := testJournal(t)
	b := &delayedBootEventBackend{fakeBackend: &fakeBackend{imageReady: true}}
	before := time.Now()
	r, err := trial(context.Background(), c, j, b, false, false)
	if err != nil || !r.Cleaned || !r.NativeAbsent || r.TimingsMS.ToValidatedDesktopMS > durationMS(b.milestone.Sub(before)) {
		t.Fatal("diagnostic delay changed validated readiness or cleanup", err)
	}
}

func TestNativeBootEventReadOnlyCommand(t *testing.T) {
	if os.Getenv("BIVOUAC_BOOT_EVENTS_NATIVE_TEST") != "1" {
		t.Skip("opt-in read-only native event query")
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{bootEventsTask, bootEventsShell, bootEventsClock} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, filepath.Join(sys, "cmd.exe"), "/d", "/s", "/c", bootEventCommand(script))
		var out boundedOutput
		cmd.Stdout = &out
		cmd.Stderr = io.Discard
		err = cmd.Run()
		cancel()
		if err != nil {
			clear(out.data)
			t.Fatal("fixed read-only query failed through native cmd transport")
		}
		_, err = parseBootEventSnapshot(out.data)
		clear(out.data)
		if err != nil {
			t.Fatal("native query did not produce bounded event metadata")
		}
	}
}

func TestDiagnosticLoggingFlagCannotAlterOrdinaryTrial(t *testing.T) {
	for _, mode := range []string{"trial", "plan", "headroom", "cleanup"} {
		err := RunCLI(context.Background(), []string{mode, "--config", "missing.json", "--boot-event-logs"}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "boot-event-logs requires build-image") {
			t.Fatal("diagnostic image flag passed non-build dispatch", mode, err)
		}
	}
}

func TestClockCalibrationPreservesDifferentClockOrigins(t *testing.T) {
	raw := []byte(`{"boot_marker":1,"clock_stable":true,"uptime_at_query_ms":40000,"event_clock_at_query_ms":20000,"clock_sample_span_ms":0,"console_event_count":0,"task_process_is_powershell":true}`)
	clock, err := parseBootEventSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	task := bootEventSnapshot{BootMarker: 1, ClockStable: true}
	r := joinBootEvents(task, task, clock)
	if r.UptimeAtQueryMS == nil || *r.UptimeAtQueryMS != 40000 || r.EventClockAtQueryMS == nil || *r.EventClockAtQueryMS != 20000 || r.ClockSampleSpanMS == nil || *r.ClockSampleSpanMS != 0 {
		t.Fatal("clock origin calibration was normalized or lost")
	}
	clock.BootMarker = 2
	r = joinBootEvents(task, task, clock)
	if r.BootMatched || r.UptimeAtQueryMS != nil || r.EventClockAtQueryMS != nil {
		t.Fatal("cross-boot calibration escaped")
	}
	clock.BootMarker = 1
	clock.ClockStable = false
	r = joinBootEvents(task, task, clock)
	if r.ClockStable || r.ClockSampleSpanMS != nil {
		t.Fatal("stepped-clock calibration escaped")
	}
}

func TestAllBootEventCommandsFitRemoteLimit(t *testing.T) {
	for _, script := range []string{bootEventsTask, bootEventsShell, bootEventsClock} {
		if len(bootEventCommand(script)) > 7800 {
			t.Fatal("fixed event command exceeds conservative remote limit")
		}
	}
}
