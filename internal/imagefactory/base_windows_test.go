//go:build windows

package imagefactory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestBaseFailureIntents(t *testing.T) {
	for _, failure := range []string{"save", "media", "create", "layout", "apply", "boot", "detach", ""} {
		t.Run(failure, func(t *testing.T) {
			r := &record{BuildID: strings.Repeat("a", 32), Workspace: `D:\Images\.builds\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, Manifest: Manifest{Media: MediaRecord{Kind: "wim", Image: MediaImage{Index: 6}}}}
			persisted := map[string]bool{}
			var calls []string
			save := func() error {
				if failure == "save" {
					return errors.New("injected persistence failure")
				}
				for k, v := range r.StorageIntents {
					persisted[k] = v
				}
				return nil
			}
			create := func(path string, gb uint32) error {
				if !persisted["base_disk"] || path != filepath.Join(r.Workspace, "source.vhdx") || gb != 127 {
					t.Fatal("unrecorded base create")
				}
				calls = append(calls, "create")
				if failure == "create" {
					return errors.New("injected create failure")
				}
				return nil
			}
			run := func(_ context.Context, script string, input any, output bool) ([]byte, error) {
				data := input.(map[string]string)
				mode := data["mode"]
				calls = append(calls, mode)
				if script != baseDisk || !output {
					t.Fatal("unexpected operation")
				}
				if !persisted["iso_mount"] {
					t.Fatal("unrecorded ISO mount")
				}
				if mode != "media" {
					for _, name := range []string{"base_attach", "esp", "msr", "windows", "esp_access", "windows_access", "temporary_letter"} {
						if !persisted[name] {
							t.Fatal("unrecorded native object", name)
						}
					}
					if r.TemporaryLetter != "Z" {
						t.Fatal("temporary letter not recorded")
					}
				}
				if mode == failure {
					return nil, &HostScriptError{Step: 50}
				}
				switch mode {
				case "media":
					return []byte(`{"volume":"\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\","letter":"Z"}`), nil
				case "layout":
					return []byte(`{"disk_guid":"{11111111-1111-1111-1111-111111111111}","esp_guid":"{22222222-2222-2222-2222-222222222222}","msr_guid":"{33333333-3333-3333-3333-333333333333}","windows_guid":"{44444444-4444-4444-4444-444444444444}"}`), nil
				case "apply":
					if !validGUID(r.Manifest.Media.Layout.WindowsGUID) {
						t.Fatal("layout not persisted before apply")
					}
					return []byte(`{"dism_version":"10.0.26300.1"}`), nil
				default:
					return []byte(`{}`), nil
				}
			}
			err := prepareBaseWith(t.Context(), testConfig(), r, save, create, run)
			if (err == nil) != (failure == "") {
				t.Fatal("failure was lost", failure, err)
			}
			if failure == "save" && len(calls) != 0 {
				t.Fatal("native work after failed intent write")
			}
			if failure == "" && !slices.Equal(calls, []string{"media", "create", "layout", "apply", "boot", "detach"}) {
				t.Fatal(calls)
			}
			if failure == "" && (r.Manifest.Media.WinRE != "unconfigured_no_recovery_partition" || r.Manifest.Media.DISMVersion == "" || len(r.Manifest.Media.BCDBootOptions) == 0) {
				t.Fatal("missing provenance")
			}
		})
	}
}

// Only ordinary temporary files and mocked Storage cmdlets are used. Fail at
// each partition/access-path boundary and prove the numbered failure survives.
func TestPartitionPlanInjected(t *testing.T) {
	for _, fail := range []int{0, 1, 2, 3, 4, 5} {
		t.Run(strconv.Itoa(fail), func(t *testing.T) {
			root := t.TempDir()
			id := strings.Repeat("b", 32)
			workspace := filepath.Join(root, id)
			if e := os.Mkdir(workspace, 0700); e != nil {
				t.Fatal(e)
			}
			for _, name := range []string{"install.iso", "source.vhdx"} {
				if e := os.WriteFile(filepath.Join(workspace, name), nil, 0600); e != nil {
					t.Fatal(e)
				}
			}
			marker, _ := json.Marshal(map[string]string{"build_id": id, "workspace": workspace})
			if e := os.WriteFile(filepath.Join(workspace, "owner.json"), marker, 0600); e != nil {
				t.Fatal(e)
			}
			mocks := `
 $script:attached=$false;$script:created=0;$script:accessCount=0
 function Get-DiskImage {param($ImagePath,$DevicePath) [pscustomobject]@{ImagePath=(Join-Path $env:BIVOUAC_FIXTURE_ROOT 'source.vhdx');Attached=$script:attached;DevicePath='\\.\PhysicalDrive123'}}
 function Mount-DiskImage {param($ImagePath,$Access,[switch]$NoDriveLetter,[switch]$PassThru) if(!$NoDriveLetter -or $Access -ne 'ReadWrite'){throw 'mount plan'};$script:attached=$true}
 function Get-Disk {param($Number) [pscustomobject]@{Number=123;Path='owned-disk-path';PartitionStyle='RAW';LogicalSectorSize=512;IsOffline=$false;Guid='{11111111-1111-1111-1111-111111111111}'}}
 function Get-Partition {param($DiskNumber)}
 function Initialize-Disk {param($Number,$PartitionStyle) if($Number -ne 123 -or $PartitionStyle -ne 'GPT'){throw 'initialize plan'}}
 function New-Partition {param($DiskNumber,$Size,$GptType,[switch]$UseMaximumSize)
  $script:created++;if($script:created -eq $env:BIVOUAC_FIXTURE_FAIL){throw 'injected boundary'}
  if($DiskNumber -ne 123){throw 'disk number'}
  if($script:created -eq 1 -and ($Size -ne 200MB -or $GptType -ine '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}')){throw 'ESP plan'}
  if($script:created -eq 2 -and ($Size -ne 16MB -or $GptType -ine '{e3c9e316-0b5c-4db8-817d-f92df00215ae}')){throw 'MSR plan'}
  if($script:created -eq 3 -and (!$UseMaximumSize -or $GptType -ine '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}')){throw 'Windows plan'}
  [pscustomobject]@{PartitionNumber=$script:created;Guid=('{'+$script:created.ToString().PadLeft(8,'0')+'-1111-1111-1111-111111111111}')}
 }
 function Format-Volume {param($Partition,$FileSystem,$Confirm) if(($Partition.PartitionNumber -eq 1 -and $FileSystem -ne 'FAT32') -or ($Partition.PartitionNumber -eq 3 -and $FileSystem -ne 'NTFS')){throw 'format plan'}}
 function Add-PartitionAccessPath {param($DiskNumber,$PartitionNumber,$AccessPath) $script:accessCount++;if(3+$script:accessCount -eq $env:BIVOUAC_FIXTURE_FAIL){throw 'injected access boundary'};if(!$AccessPath.StartsWith($env:BIVOUAC_FIXTURE_ROOT)){throw 'foreign access path'}}
 `
			path := filepath.Join(workspace, "fixture.ps1")
			if e := os.WriteFile(path, []byte(mocks+baseDisk), 0600); e != nil {
				t.Fatal(e)
			}
			t.Setenv("BIVOUAC_FIXTURE_FAIL", strconv.Itoa(fail))
			t.Setenv("BIVOUAC_FIXTURE_ROOT", workspace)
			input, _ := json.Marshal(map[string]string{"root": root, "instance_id": id, "mode": "layout"})
			b, e := executeHost(t.Context(), path, input, true)
			if fail == 0 {
				var layout DiskLayout
				if e != nil || json.Unmarshal(b, &layout) != nil || !validGUID(layout.WindowsGUID) {
					t.Fatal("partition plan failed", e)
				}
			} else {
				var step *HostScriptError
				if !errors.As(e, &step) {
					t.Fatal("failure lost")
				}
				want := 40 + fail
				if fail > 3 {
					want = 44
				}
				if step.Step != want {
					t.Fatal("wrong boundary", step.Step, want)
				}
			}
		})
	}
}

func TestCleanupNewStorageObjectsInjected(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("c", 32)
	workspace := filepath.Join(root, id)
	if e := os.Mkdir(workspace, 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"disk.vhdx", "source.vhdx", "install.iso"} {
		if e := os.WriteFile(filepath.Join(workspace, name), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	marker, _ := json.Marshal(map[string]string{"build_id": id, "workspace": workspace})
	if e := os.WriteFile(filepath.Join(workspace, "owner.json"), marker, 0600); e != nil {
		t.Fatal(e)
	}
	trace := filepath.Join(workspace, "trace.txt")
	t.Setenv("BIVOUAC_FIXTURE_ROOT", workspace)
	t.Setenv("BIVOUAC_FIXTURE_TRACE", trace)
	mocks := `
 $script:detached=@{}
 function Get-DiskImage {param($ImagePath) [pscustomobject]@{Attached=(!$script:detached[$ImagePath]);DevicePath='\\.\PhysicalDrive123'} }
 function Get-Disk { [pscustomobject]@{Number=123} }
 function Get-Partition {param($DiskNumber) [pscustomobject]@{PartitionNumber=1;GptType='{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}';AccessPaths=@(((Join-Path $env:BIVOUAC_FIXTURE_ROOT 'base-esp')+'\'),'Z:\','Q:\')} }
 function Remove-PartitionAccessPath {param($DiskNumber,$PartitionNumber,$AccessPath) if($AccessPath -eq 'Q:\'){throw 'foreign letter'};[IO.File]::AppendAllText($env:BIVOUAC_FIXTURE_TRACE,'access;') }
 function Dismount-DiskImage {param($ImagePath) $script:detached[$ImagePath]=$true;[IO.File]::AppendAllText($env:BIVOUAC_FIXTURE_TRACE,([IO.Path]::GetFileName($ImagePath)+';')) }
 `
	file := filepath.Join(workspace, "cleanup-fixture.ps1")
	if e := os.WriteFile(file, []byte(mocks+detachDisk), 0600); e != nil {
		t.Fatal(e)
	}
	r := &record{BuildID: id, Workspace: workspace, TemporaryLetter: "Z", StorageIntents: map[string]bool{"child_attach": true, "base_attach": true, "iso_mount": true, "temporary_letter": true}}
	input, _ := json.Marshal(r.scriptData())
	if _, e := executeHost(t.Context(), file, input, false); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(trace)
	if e != nil || string(b) != "access;disk.vhdx;access;access;source.vhdx;install.iso;" {
		t.Fatal("cleanup skipped an object or touched a foreign letter", string(b))
	}
}
