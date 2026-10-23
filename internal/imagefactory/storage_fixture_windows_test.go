//go:build windows

package imagefactory

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// All Storage commands, executables, signatures and registry lookups are mocked.
// Only ordinary temporary files are used. Persisted model state lets the actual
// cleanup helper consume what a failed layout/apply/boot invocation left behind.
const storageFixturePS = `
 $fixture=Get-Content -LiteralPath $env:BIVOUAC_STORAGE_FIXTURE -Raw|ConvertFrom-Json
 $state=Get-Content -LiteralPath $fixture.state -Raw|ConvertFrom-Json
 function Save-Fixture {$state|ConvertTo-Json -Depth 8 -Compress|Set-Content -LiteralPath $fixture.state;if($fixture.fail_after -and $fixture.fail_after -eq $script:lastCall){throw 'injected lost creation response'}}
 function Trace([string]$Name){$script:lastCall=$Name;[IO.File]::AppendAllText($fixture.trace,($Name+[Environment]::NewLine));if($fixture.fail -eq $Name){throw 'injected operation failure'}}
 function Get-FixtureParts {
  $types=@('{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}','{e3c9e316-0b5c-4db8-817d-f92df00215ae}','{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}')
  $sizes=@(200MB,16MB,1GB);$offsets=@(1MB,201MB,217MB)
  for($i=0;$i -lt $state.parts;$i++){
   $access=@('Q:\')
   if($i -eq 0){if($state.esp_access){$access+=((Join-Path $fixture.workspace 'base-esp')+'\')};if($state.letter){$access+='Z:\'}}
   if($i -eq 2){if($state.windows_access){$access+=((Join-Path $fixture.workspace 'base-windows')+'\')};if($state.inspection_access){$access+=((Join-Path $fixture.workspace 'inspect-mount')+'\')};if($state.staging_access){$access+=((Join-Path $fixture.workspace 'setup-private\mount')+'\')}}
   [pscustomobject]@{PartitionNumber=($i+1);Guid=$fixture.guids[$i];GptType=$types[$i];Size=$sizes[$i];Offset=$offsets[$i];AccessPaths=$access}
  }
 }
 function Get-DiskImage {param($ImagePath,$DevicePath)
  $source=Join-Path $fixture.workspace 'source.vhdx'
  if($DevicePath){if($fixture.refuse -eq 'backing'){$source=Join-Path $fixture.workspace 'foreign.vhdx'};return [pscustomobject]@{ImagePath=$source}}
  $attached=$state.base_attached;if($ImagePath.EndsWith('install.iso')){$attached=$state.iso_attached};if($ImagePath.EndsWith('disk.vhdx')){$attached=$state.child_attached}
  $device='\\.\PhysicalDrive123';if($fixture.refuse -eq 'device'){$device='\\.\PhysicalDrive124'}
  [pscustomobject]@{Attached=$attached;DevicePath=$device}
 }
 function Mount-DiskImage {param($ImagePath,$Access,[switch]$NoDriveLetter,[switch]$PassThru)
  if(!$NoDriveLetter){throw 'persistent letter in mount plan'}
  if($ImagePath.EndsWith('install.iso')){Trace 'mount_iso';if($Access -ne 'ReadOnly'){throw 'ISO access'};$state.iso_attached=$true}else{Trace 'mount_base';if($Access -ne 'ReadWrite'){throw 'base access'};$state.base_attached=$true}
  Save-Fixture
 }
 function Get-Disk {param($Number)
  $path='owned-storage-path';if($Number -and $fixture.refuse -eq 'storage'){$path='foreign-storage-path'}
  $style=$state.style;if($fixture.refuse -eq 'nonraw'){$style='GPT'}
  $sector=512;if($fixture.refuse -eq 'sector'){$sector=4096}
  $guid=$fixture.disk_guid;if($fixture.refuse -eq 'disk_guid'){$guid='{ffffffff-ffff-ffff-ffff-ffffffffffff}'}
  [pscustomobject]@{Number=123;Path=$path;PartitionStyle=$style;LogicalSectorSize=$sector;IsOffline=$state.offline;Guid=$guid;NumberOfPartitions=$state.parts}
 }
 function Get-Partition {[CmdletBinding()]param($DiskNumber)
  if($state.parts -eq 0){Write-Error -Message 'no matching partitions' -Category ObjectNotFound -ErrorId CmdletizationQuery_NotFound_DiskNumber;return}
  $parts=@(Get-FixtureParts)
  if($fixture.refuse -eq 'partition_guid'){$parts[0].Guid='{ffffffff-ffff-ffff-ffff-ffffffffffff}'}
  if($fixture.refuse -eq 'windows_guid'){$parts[2].Guid='{ffffffff-ffff-ffff-ffff-ffffffffffff}'}
  if($fixture.refuse -eq 'access'){$parts[0].AccessPaths=@()}
  if($state.parts -eq 3){switch($fixture.table){
   'extra' {$parts+=[pscustomobject]@{Guid='{ffffffff-ffff-ffff-ffff-ffffffffffff}';Offset=0;GptType='{e3c9e316-0b5c-4db8-817d-f92df00215ae}';Size=16MB}}
   'order' {$parts[1].Offset=0}
   'guid' {$parts[1].Guid='{ffffffff-ffff-ffff-ffff-ffffffffffff}'}
   'type' {$parts[1].GptType=$parts[0].GptType}
   'size' {$parts[0].Size=199MB}
  }}
  $parts
 }
 function Set-Disk {param($Number,$IsOffline) Trace 'set_disk';$state.offline=$IsOffline;Save-Fixture}
 function Initialize-Disk {param($Number,$PartitionStyle) Trace 'initialize';if($Number -ne 123 -or $PartitionStyle -ne 'GPT'){throw 'initialize plan'};$state.style='GPT';Save-Fixture}
 function New-Partition {param($DiskNumber,$Size,$GptType,[switch]$UseMaximumSize)
  $names=@('esp','msr','windows');Trace $names[$state.parts]
  if($DiskNumber -ne 123){throw 'disk number'}
  if($state.parts -eq 0 -and ($Size -ne 200MB -or $GptType -ine '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}')){throw 'ESP plan'}
  if($state.parts -eq 1 -and ($Size -ne 16MB -or $GptType -ine '{e3c9e316-0b5c-4db8-817d-f92df00215ae}')){throw 'MSR plan'}
  if($state.parts -eq 2 -and (!$UseMaximumSize -or $GptType -ine '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}')){throw 'Windows plan'}
  $state.parts++;Save-Fixture;@(Get-FixtureParts)[-1]
 }
 function Format-Volume {param($Partition,$FileSystem,$Confirm)
  if($Partition.PartitionNumber -eq 1){Trace 'format_esp';if($FileSystem -ne 'FAT32'){throw 'ESP format'}}else{Trace 'format_windows';if($FileSystem -ne 'NTFS'){throw 'Windows format'}}
 }
 function Add-PartitionAccessPath {param($DiskNumber,$PartitionNumber,$AccessPath)
  if($DiskNumber -ne 123){throw 'disk number'}
  if($AccessPath -eq 'Z:\'){Trace 'letter';$state.letter=$true}
  elseif($AccessPath -eq ((Join-Path $fixture.workspace 'base-windows')+'\')){Trace 'access_windows';$state.windows_access=$true}
  elseif($AccessPath -eq ((Join-Path $fixture.workspace 'base-esp')+'\')){Trace 'access_esp';$state.esp_access=$true}
  else{throw 'foreign access path'};Save-Fixture
 }
 function Remove-PartitionAccessPath {param($DiskNumber,$PartitionNumber,$AccessPath)
  switch($AccessPath){
   'Z:\' {Trace 'remove_letter';$state.letter=$false}
   ((Join-Path $fixture.workspace 'base-windows')+'\') {Trace 'remove_windows';$state.windows_access=$false}
   ((Join-Path $fixture.workspace 'base-esp')+'\') {Trace 'remove_esp';$state.esp_access=$false}
   ((Join-Path $fixture.workspace 'inspect-mount')+'\') {Trace 'remove_inspection';$state.inspection_access=$false}
   ((Join-Path $fixture.workspace 'setup-private\mount')+'\') {Trace 'remove_staging';$state.staging_access=$false}
   default {throw 'foreign access path removal'}
  };Save-Fixture
 }
 function Dismount-DiskImage {param($ImagePath)
  if($ImagePath.EndsWith('install.iso')){Trace 'detach_iso';$state.iso_attached=$false}
  elseif($ImagePath.EndsWith('source.vhdx')){Trace 'detach_base';$state.base_attached=$false}
  else{Trace 'detach_child';$state.child_attached=$false};Save-Fixture
 }
 function Get-Volume {
  $path=$fixture.volume;if($fixture.refuse -eq 'media_changed'){$path='\\?\Volume{ffffffff-ffff-ffff-ffff-ffffffffffff}\'}
  $letter='';if($fixture.refuse -eq 'letter_collision'){$letter='Z'}
  [pscustomobject]@{Path=$path;DriveLetter=$letter}
 }
 function Get-PSDrive {param($PSProvider)}
 function Test-Path {param($LiteralPath,$PathType)
  if($LiteralPath -like '*\base-esp\EFI\*'){return $fixture.refuse -ne 'missing_artifact'}
  Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath
 }
 function Get-Item {param($LiteralPath,[switch]$Force)
  if($LiteralPath -match '\\System32\\(?:dism|bcdboot)\.exe$'){return [pscustomobject]@{VersionInfo=[pscustomobject]@{FileMajorPart=10;FileMinorPart=0;FileBuildPart=26300;FilePrivatePart=1}}}
  Microsoft.PowerShell.Management\Get-Item -Force -LiteralPath $LiteralPath
 }
 function Invoke-ImageTool([string]$Path,[string[]]$Arguments){
  $tool='dism';if($Path.EndsWith('bcdboot.exe')){$tool='bcdboot'}
  $state.tool_args=$Arguments;Save-Fixture;Trace ('tool_'+$tool)
  if($fixture.refuse -eq 'tool_exit'){return 5};return 0
 }
 function Get-AuthenticodeSignature {param($LiteralPath)
  $status='Valid';$issuer='CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation'
  switch($fixture.refuse){'unsigned' {$status='NotSigned'};'invalid_signature' {$status='HashMismatch'};'issuer2023' {$issuer='CN=Windows UEFI CA 2023, O=Microsoft Corporation'};'unknown_issuer' {$issuer='CN=Unrecognized'}}
  [pscustomobject]@{Status=$status;SignerCertificate=[pscustomobject]@{Issuer=$issuer}}
 }
 function Get-MountedDeviceNames{if($fixture.refuse -eq 'mapping_unreadable'){throw 'unavailable'};$fixture.reservations}
 function Get-MountedDeviceMapping([string]$Letter){
  if($fixture.refuse -eq 'mapping_unreadable'){throw 'unavailable'}
  if($fixture.foreign_mapping){return ,([byte[]]([Text.Encoding]::ASCII.GetBytes('DMIO:ID:')+([Guid]'{ffffffff-ffff-ffff-ffff-ffffffffffff}').ToByteArray()))}
  if($state.letter -or $fixture.stale_mapping){return ,([byte[]]([Text.Encoding]::ASCII.GetBytes('DMIO:ID:')+([Guid]$fixture.guids[0]).ToByteArray()))}
  return $null
 }
`

type storageFixture struct {
	t                                                      *testing.T
	workspace, root, id, optionsPath, statePath, tracePath string
	options, state                                         map[string]any
}

func newStorageFixture(t *testing.T, mode string) *storageFixture {
	t.Helper()
	root := t.TempDir()
	id := strings.Repeat("b", 32)
	workspace := filepath.Join(root, id)
	if e := os.Mkdir(workspace, 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"install.iso", "source.vhdx", "disk.vhdx"} {
		if e := os.WriteFile(filepath.Join(workspace, name), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeFixtureJSON(t, filepath.Join(workspace, "owner.json"), map[string]string{"build_id": id, "workspace": workspace})
	f := &storageFixture{t: t, workspace: workspace, root: root, id: id, optionsPath: filepath.Join(root, "fixture.json"), statePath: filepath.Join(root, "state.json"), tracePath: filepath.Join(root, "trace.txt")}
	f.options = map[string]any{"workspace": workspace, "state": f.statePath, "trace": f.tracePath, "fail": "", "fail_after": "", "refuse": "", "table": "", "stale_mapping": false, "disk_guid": "{11111111-1111-1111-1111-111111111111}", "guids": []string{"{22222222-2222-2222-2222-222222222222}", "{33333333-3333-3333-3333-333333333333}", "{44444444-4444-4444-4444-444444444444}"}, "volume": `\\?\Volume{55555555-5555-5555-5555-555555555555}\`}
	later := mode != "layout" && mode != "media"
	style := "RAW"
	parts := 0
	if later {
		style = "GPT"
		parts = 3
	}
	f.state = map[string]any{"style": style, "parts": parts, "offline": true, "base_attached": later, "iso_attached": mode != "media", "child_attached": false, "windows_access": later, "esp_access": later, "inspection_access": false, "staging_access": false, "letter": false, "tool_args": []string{}}
	t.Setenv("BIVOUAC_STORAGE_FIXTURE", f.optionsPath)
	writeFixtureJSON(t, f.statePath, f.state)
	return f
}
func writeFixtureJSON(t *testing.T, path string, value any) {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func (f *storageFixture) data(mode string) map[string]string {
	return map[string]string{"root": f.root, "instance_id": f.id, "disk": filepath.Join(f.workspace, "disk.vhdx"), "mode": mode, "kind": "wim", "index": "6", "letter": "Z", "temporary_letter": "Z", "disk_guid": f.options["disk_guid"].(string), "esp_guid": f.options["guids"].([]string)[0], "windows_guid": f.options["guids"].([]string)[2], "volume": f.options["volume"].(string)}
}
func (f *storageFixture) run(script string, data map[string]string) ([]byte, error) {
	f.t.Helper()
	writeFixtureJSON(f.t, f.optionsPath, f.options)
	script = strings.Replace(script, "\ntry{", "\n"+storageFixturePS+"\ntry{", 1)
	path := filepath.Join(f.root, "run.ps1")
	if e := os.WriteFile(path, []byte(script), 0600); e != nil {
		f.t.Fatal(e)
	}
	b, _ := json.Marshal(data)
	return executeHost(f.t.Context(), path, b, true)
}
func (f *storageFixture) trace() []string {
	f.t.Helper()
	b, e := os.ReadFile(f.tracePath)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		f.t.Fatal(e)
	}
	return strings.Fields(string(b))
}
func (f *storageFixture) readState() map[string]any {
	f.t.Helper()
	b, e := os.ReadFile(f.statePath)
	if e != nil {
		f.t.Fatal(e)
	}
	var s map[string]any
	if json.Unmarshal(b, &s) != nil {
		f.t.Fatal("invalid fixture state")
	}
	return s
}
func requireScriptStep(t *testing.T, err error, want int) {
	t.Helper()
	var step *HostScriptError
	if !errors.As(err, &step) || step.Step != want {
		t.Fatalf("script step: got %v, want %d", err, want)
	}
}

func TestBaseLetterReservations(t *testing.T) {
	t.Run("selection", func(t *testing.T) {
		f := newStorageFixture(t, "media")
		f.options["reservations"] = []string{`\DosDevices\z:`, `\DosDevices\Y:`, `\DosDevices\X:other`, `\??\Volume{foreign}`}
		b, e := f.run(baseDisk, f.data("media"))
		var result struct{ Letter string }
		if e != nil || json.Unmarshal(b, &result) != nil || result.Letter != "X" {
			t.Fatal("selection did not skip reserved absent devices", e)
		}
	})
	t.Run("reservation_after_selection", func(t *testing.T) {
		f := newStorageFixture(t, "boot")
		f.options["reservations"] = []string{`\DosDevices\Z:`}
		_, e := f.run(baseDisk, f.data("boot"))
		requireScriptStep(t, e, 60)
		if len(f.trace()) != 0 {
			t.Fatal("reserved letter taken during boot")
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		f := newStorageFixture(t, "media")
		f.options["refuse"] = "mapping_unreadable"
		_, e := f.run(baseDisk, f.data("media"))
		requireScriptStep(t, e, 20)
	})
}

func TestGPTLetterMappingBytes(t *testing.T) {
	helpers, _, ok := strings.Cut(detachDisk, "\ntry{")
	if !ok {
		t.Fatal("cleanup helper boundary absent")
	}
	// This asymmetric GUID makes textual/network byte order differ from the
	// Windows binary GUID layout. No registry or native Storage command runs.
	script := helpers + `
$guid='{00112233-4455-6677-8899-aabbccddeeff}'
[byte[]]$owned=68,77,73,79,58,73,68,58,51,34,17,0,85,68,119,102,136,153,170,187,204,221,238,255
if(!(Test-GPTLetterMapping $owned $guid)){throw 'owned mapping rejected'}
$foreign=$owned.Clone();$foreign[8]=0
$prefix=$owned.Clone();$prefix[0]=0
[byte[]]$network=68,77,73,79,58,73,68,58,0,17,34,51,68,85,102,119,136,153,170,187,204,221,238,255
foreach($value in @($null,'DMIO:ID:',([byte[]]@()),$foreign,$prefix,$network,([byte[]]$owned[0..22]),([byte[]]($owned+0)))){
 if(Test-GPTLetterMapping $value $guid){throw 'foreign mapping claimed'}
}
[Console]::Out.WriteLine('BIVOUAC_IMAGE_RESULT')
[Console]::Out.WriteLine('{}')
`
	path := filepath.Join(t.TempDir(), "mapping.ps1")
	if e := os.WriteFile(path, []byte(script), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := executeHost(t.Context(), path, nil, true); e != nil {
		t.Fatal("mapping byte comparison", e)
	}
}

func TestForeignLetterMappingBuildAndCleanup(t *testing.T) {
	f := newStorageFixture(t, "boot")
	if _, e := f.run(baseDisk, f.data("boot")); e != nil {
		t.Fatal("boot failed", e)
	}
	if _, e := f.run(baseDisk, f.data("detach")); e != nil {
		t.Fatal("build detach failed", e)
	}
	// Another device reserves the recorded letter after the factory releases it.
	f.options["foreign_mapping"] = true
	b, e := f.cleanup()
	var result struct {
		Letter string `json:"retained_letter"`
	}
	if e != nil || json.Unmarshal(b, &result) != nil || result.Letter != "" {
		t.Fatal("foreign mapping retained a completed build", e)
	}
	if calls := f.trace(); slices.Contains(calls[slices.Index(calls, "detach_base")+1:], "remove_letter") {
		t.Fatal("cleanup touched a foreign reservation")
	}
}

func TestBaseLayoutSafetyRefusals(t *testing.T) {
	for _, refuse := range []string{"device", "backing", "storage", "nonraw", "sector", "existing_partitions"} {
		t.Run(refuse, func(t *testing.T) {
			f := newStorageFixture(t, "layout")
			f.options["refuse"] = refuse
			if refuse == "existing_partitions" {
				f.state["parts"] = 1
				writeFixtureJSON(t, f.statePath, f.state)
			}
			_, e := f.run(baseDisk, f.data("layout"))
			want := 30
			if refuse == "nonraw" || refuse == "sector" || refuse == "existing_partitions" {
				want = 40
			}
			requireScriptStep(t, e, want)
			if !slices.Equal(f.trace(), []string{"mount_base"}) {
				t.Fatal("mutation after safety refusal", f.trace())
			}
		})
	}
}
func TestBaseExactPartitionTable(t *testing.T) {
	for _, fault := range []string{"", "extra", "order", "guid", "type", "size"} {
		t.Run(fault, func(t *testing.T) {
			f := newStorageFixture(t, "layout")
			f.options["table"] = fault
			b, e := f.run(baseDisk, f.data("layout"))
			if fault == "" {
				var layout DiskLayout
				if e != nil || json.Unmarshal(b, &layout) != nil || layout.WindowsGUID != f.data("layout")["windows_guid"] {
					t.Fatal("valid table refused", e)
				}
			} else {
				requireScriptStep(t, e, 44)
				if slices.Contains(f.trace(), "access_windows") {
					t.Fatal("access path added after bad table")
				}
			}
		})
	}
}
func TestBaseLaterIdentityRefusals(t *testing.T) {
	for _, mode := range []string{"apply", "boot", "detach"} {
		for _, refuse := range []string{"disk_guid", "partition_guid", "windows_guid", "access"} {
			t.Run(mode+"_"+refuse, func(t *testing.T) {
				f := newStorageFixture(t, mode)
				f.options["refuse"] = refuse
				_, e := f.run(baseDisk, f.data(mode))
				requireScriptStep(t, e, 30)
				if len(f.trace()) != 0 {
					t.Fatal("mutation after GUID/access refusal", f.trace())
				}
			})
		}
	}
}
func TestBaseApplyArgumentsAndMediaChange(t *testing.T) {
	for _, kind := range []string{"wim", "esd", "swm"} {
		t.Run(kind, func(t *testing.T) {
			f := newStorageFixture(t, "apply")
			data := f.data("apply")
			data["kind"] = kind
			b, e := f.run(baseDisk, data)
			if e != nil {
				t.Fatal(e)
			}
			var result struct {
				Version string `json:"dism_version"`
			}
			if json.Unmarshal(b, &result) != nil || !numericVersion(result.Version) {
				t.Fatal("DISM version missing")
			}
			raw, _ := json.Marshal(f.readState()["tool_args"])
			var args []string
			_ = json.Unmarshal(raw, &args)
			want := []string{"/Apply-Image", "/ImageFile:" + data["volume"] + `sources\install.` + kind, "/Index:6", "/ApplyDir:" + filepath.Join(f.workspace, "base-windows"), "/CheckIntegrity", "/LogPath:" + filepath.Join(f.workspace, "apply.log")}
			if kind == "swm" {
				want = append(want, "/SWMFile:"+data["volume"]+`sources\install*.swm`)
			}
			if !slices.Equal(args, want) {
				t.Fatal("wrong DISM argument array")
			}
		})
	}
	f := newStorageFixture(t, "apply")
	f.options["refuse"] = "media_changed"
	_, e := f.run(baseDisk, f.data("apply"))
	requireScriptStep(t, e, 50)
	if len(f.trace()) != 0 {
		t.Fatal("DISM ran after changed media")
	}
}
func TestBaseBootSignaturesAndFailureLetterCleanup(t *testing.T) {
	for _, refuse := range []string{"", "letter_collision", "tool_exit", "missing_artifact", "unsigned", "invalid_signature", "issuer2023", "unknown_issuer"} {
		t.Run(refuse, func(t *testing.T) {
			f := newStorageFixture(t, "boot")
			f.options["refuse"] = refuse
			b, e := f.run(baseDisk, f.data("boot"))
			if refuse == "" {
				var result struct {
					Version string      `json:"bcdboot_version"`
					Issuers BootIssuers `json:"boot_issuers"`
				}
				if e != nil || json.Unmarshal(b, &result) != nil || !numericVersion(result.Version) || result.Issuers.Fallback != "windows_production_pca_2011" || result.Issuers.Microsoft != "windows_production_pca_2011" {
					t.Fatal("invalid signed boot result", e)
				}
			} else {
				requireScriptStep(t, e, 60)
			}
			trace := f.trace()
			if refuse == "letter_collision" {
				if len(trace) != 0 {
					t.Fatal("letter collision mutated storage")
				}
				return
			}
			if !slices.Contains(trace, "remove_letter") || f.readState()["letter"] != false {
				t.Fatal("temporary letter survived boot failure")
			}
			raw, _ := json.Marshal(f.readState()["tool_args"])
			var args []string
			_ = json.Unmarshal(raw, &args)
			if !slices.Equal(args, []string{filepath.Join(f.workspace, `base-windows\Windows`), "/s", "Z:", "/f", "UEFI", "/offline", "/nofirmwaresync"}) {
				t.Fatal("host firmware/offline BCDBoot argument contract violated")
			}
		})
	}
}

func fixtureCleanupIntents() map[string]bool {
	return map[string]bool{"iso_mount": true, "base_attach": true, "child_attach": true, "windows_access": true, "esp_access": true, "inspection_access": true, "staging_access": true, "temporary_letter": true}
}
func (f *storageFixture) cleanup() ([]byte, error) {
	data := f.data("cleanup")
	intents, _ := json.Marshal(fixtureCleanupIntents())
	data["storage_intents"] = string(intents)
	return f.run(detachDisk, data)
}
func TestCleanupAfterEveryNativeBoundary(t *testing.T) {
	cases := []struct {
		mode, fail string
		step       int
	}{{"media", "mount_iso", 20}, {"layout", "mount_base", 30}, {"layout", "set_disk", 40}, {"layout", "initialize", 40}, {"layout", "esp", 41}, {"layout", "format_esp", 41}, {"layout", "msr", 42}, {"layout", "windows", 43}, {"layout", "format_windows", 43}, {"layout", "access_windows", 46}, {"layout", "access_esp", 46}, {"apply", "tool_dism", 50}, {"boot", "letter", 60}, {"boot", "tool_bcdboot", 60}, {"boot", "remove_letter", 60}, {"detach", "remove_windows", 70}, {"detach", "remove_esp", 70}, {"detach", "detach_base", 70}, {"detach", "detach_iso", 70}}
	for _, test := range cases {
		t.Run(test.fail, func(t *testing.T) {
			f := newStorageFixture(t, test.mode)
			f.options["fail"] = test.fail
			_, e := f.run(baseDisk, f.data(test.mode))
			requireScriptStep(t, e, test.step)
			f.options["fail"] = ""
			b, e := f.cleanup()
			if e != nil {
				t.Fatal("failure cleanup failed", e)
			}
			var result struct {
				Letter string `json:"retained_letter"`
			}
			if json.Unmarshal(b, &result) != nil || result.Letter != "" {
				t.Fatal("unexpected retained letter")
			}
			state := f.readState()
			for _, name := range []string{"base_attached", "iso_attached", "child_attached", "letter"} {
				if state[name] != false {
					t.Fatal("cleanup leaked native object", name)
				}
			}
			if test.fail == "set_disk" || test.fail == "initialize" || test.fail == "esp" {
				trace := f.trace()
				if !slices.Contains(trace, "detach_base") || !slices.Contains(trace, "detach_iso") {
					t.Fatal("RAW/empty base or ISO did not detach")
				}
			}
		})
	}
}
func TestCleanupAccessIntentsAndStaleLetter(t *testing.T) {
	for _, test := range []string{"all", "no_access_intents", "reboot_mapping", "foreign_mapping", "mapping_unreadable", "detached_no_mapping"} {
		t.Run(test, func(t *testing.T) {
			f := newStorageFixture(t, "boot")
			f.state["child_attached"] = true
			f.state["inspection_access"] = true
			f.state["staging_access"] = true
			if strings.HasPrefix(test, "reboot") || strings.HasPrefix(test, "mapping") || test == "detached_no_mapping" {
				f.state["base_attached"] = false
				f.state["child_attached"] = false
				f.options["stale_mapping"] = test != "detached_no_mapping"
			}
			if test == "mapping_unreadable" {
				f.options["refuse"] = test
			}
			if test == "foreign_mapping" {
				f.options["foreign_mapping"] = true
			}
			writeFixtureJSON(t, f.statePath, f.state)
			data := f.data("cleanup")
			intents := fixtureCleanupIntents()
			if test == "no_access_intents" {
				for _, key := range []string{"windows_access", "esp_access", "staging_access", "inspection_access"} {
					delete(intents, key)
				}
			}
			raw, _ := json.Marshal(intents)
			data["storage_intents"] = string(raw)
			b, e := f.run(detachDisk, data)
			if e != nil {
				t.Fatal(e)
			}
			var result struct {
				Letter string `json:"retained_letter"`
			}
			if json.Unmarshal(b, &result) != nil {
				t.Fatal("invalid cleanup result")
			}
			retained := test == "reboot_mapping" || test == "mapping_unreadable"
			if (result.Letter == "Z") != retained {
				t.Fatal("stale letter retention wrong")
			}
			if test == "foreign_mapping" && slices.Contains(f.trace(), "remove_letter") {
				t.Fatal("foreign mapping touched")
			}
			if test == "all" {
				for _, call := range []string{"remove_windows", "remove_esp", "remove_inspection", "remove_staging"} {
					if !slices.Contains(f.trace(), call) {
						t.Fatal("intent was not consumed", call)
					}
				}
			}
			if test == "no_access_intents" {
				for _, call := range f.trace() {
					if strings.HasPrefix(call, "remove_") {
						t.Fatal("unrecorded access path removed")
					}
				}
			}
		})
	}
}

func TestCleanupAfterAmbiguousCreationResponses(t *testing.T) {
	for _, test := range []struct {
		mode, call string
		step       int
	}{{"media", "mount_iso", 20}, {"layout", "mount_base", 30}, {"boot", "letter", 60}} {
		t.Run(test.call, func(t *testing.T) {
			f := newStorageFixture(t, test.mode)
			f.options["fail_after"] = test.call
			_, e := f.run(baseDisk, f.data(test.mode))
			requireScriptStep(t, e, test.step)
			f.options["fail_after"] = ""
			if _, e = f.cleanup(); e != nil {
				t.Fatal("cleanup after ambiguous creation failed", e)
			}
			state := f.readState()
			for _, name := range []string{"base_attached", "iso_attached", "letter"} {
				if state[name] != false {
					t.Fatal("ambiguous creation leaked", name)
				}
			}
		})
	}
}
