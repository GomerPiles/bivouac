//go:build windows

package imagefactory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
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
				if !persisted["base_attach"] || path != filepath.Join(r.Workspace, "source.vhdx") || gb != 127 {
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
					for _, name := range []string{"base_attach", "esp_access", "windows_access"} {
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
				case "boot":
					if !persisted["temporary_letter"] {
						t.Fatal("unrecorded temporary letter")
					}
					return []byte(`{"bcdboot_version":"10.0.26300.1","boot_issuers":{"fallback":"windows_production_pca_2011","microsoft":"windows_production_pca_2011"}}`), nil
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
			if failure == "" && (r.Manifest.Media.WinRE != "apply_time_no_recovery_partition_not_registered_by_factory" || r.Manifest.Media.DISMVersion == "" || !numericVersion(r.Manifest.Media.BCDBootVersion) || r.Manifest.Media.BootIssuers.Fallback != "windows_production_pca_2011" || r.Manifest.Media.BootIssuers.Microsoft != "windows_production_pca_2011" || !slices.Contains(r.Manifest.Media.BCDBootOptions, "/offline") || !slices.Contains(r.Manifest.Media.BCDBootOptions, "/nofirmwaresync") || slices.Contains(r.Manifest.Media.BCDBootOptions, "/bootex")) {
				t.Fatal("missing provenance")
			}
			if failure != "" && failure != "save" {
				removed := false
				e := cleanupOwned(nil, func() error { return nil }, func() error {
					return detachOwnedWith(t.Context(), r, func(_ context.Context, script string, input any, output bool) ([]byte, error) {
						if script != detachDisk || !output {
							t.Fatal("wrong cleanup helper")
						}
						var intents map[string]bool
						if json.Unmarshal([]byte(input.(map[string]string)["storage_intents"]), &intents) != nil {
							t.Fatal("missing cleanup intents")
						}
						for name := range persisted {
							if !intents[name] {
								t.Fatal("cleanup lost persisted ownership", name)
							}
						}
						return []byte(`{"retained_letter":""}`), nil
					})
				}, func() error { removed = true; return nil })
				if e != nil || !removed {
					t.Fatal("orchestration failure did not allow owned cleanup", e)
				}
			}
		})
	}
}

func TestRetainedLetterStopsDeletionAndPersists(t *testing.T) {
	r := &record{TemporaryLetter: "Z", StorageIntents: map[string]bool{"temporary_letter": true}}
	removed := false
	e := cleanupOwned(nil, func() error { return nil }, func() error {
		return detachOwnedWith(t.Context(), r, func(context.Context, string, any, bool) ([]byte, error) {
			return []byte(`{"retained_letter":"Z"}`), nil
		})
	}, func() error { removed = true; return nil })
	var retained *RetainedLetterError
	b, _ := json.Marshal(r)
	if !errors.As(e, &retained) || retained.Letter != "Z" || removed || !strings.Contains(string(b), `"retained_letter":"Z"`) {
		t.Fatal("ambiguous mapping lost ownership/diagnostics")
	}
}

// The real helper, not the fixture's replacement: a tool that writes to
// stderr must still report its own exit code under Windows PowerShell 5.1.
func TestImageToolStderrKeepsExitCode(t *testing.T) {
	start := strings.Index(baseDisk, "function Invoke-ImageTool(")
	end := strings.Index(baseDisk[start:], "\n") + start
	if start < 0 || end <= start {
		t.Fatal("Invoke-ImageTool not found")
	}
	cmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	script := "$ErrorActionPreference='Stop'\n" + baseDisk[start:end] + "\n" +
		"[Console]::Out.Write((Invoke-ImageTool '" + cmd + "' @('/c','echo','tool-error','1>&2','&','exit','3')))"
	if got := runTestPS(t, script, nil); got != "3" {
		t.Fatalf("exit code lost after stderr: %q", got)
	}
}
