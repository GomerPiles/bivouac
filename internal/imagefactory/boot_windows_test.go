//go:build windows

package imagefactory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func bootFixtureSources() []string {
	return []string{
		`Windows\Boot\EFI\bootmgfw.efi`, `Windows\Boot\EFI\bootmgr.efi`,
		`Windows\Boot\EFI\memtest.efi`, `Windows\Boot\EFI\SecureBootRecovery.efi`,
		`Windows\Boot\EFI\boot.pnd.stl`, `Windows\Boot\EFI\boot.stl`,
		`Windows\Boot\EFI\en-US\bootmgfw.efi.mui`,
		`Windows\Boot\Fonts\wgl4_boot.ttf`, `Windows\Boot\Resources\bootres.dll`,
		`Windows\Boot\Resources\en-US\bootres.dll.mui`,
		`Windows\System32\winload.efi`,
		`Windows\Boot\EFI_EX\bootmgfw.efi`,
	}
}

func createBootFixtureFiles(t *testing.T, workspace string) {
	t.Helper()
	for _, root := range []string{"base-windows", "base-esp"} {
		if e := os.MkdirAll(filepath.Join(workspace, root), 0700); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range bootFixtureSources() {
		path := filepath.Join(workspace, "base-windows", name)
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, []byte("image:"+name), 0600); e != nil {
			t.Fatal(e)
		}
	}
}

func TestBootCopySet(t *testing.T) {
	f := newStorageFixture(t, "boot")
	if _, e := f.run(baseDisk, f.data("boot")); e != nil {
		t.Fatal(e)
	}
	want := map[string]string{
		`EFI\Boot\bootx64.efi`:   `image:Windows\Boot\EFI\bootmgfw.efi`,
		`EFI\Microsoft\Boot\BCD`: "scratch-store",
	}
	for _, name := range bootFixtureSources() {
		if strings.HasPrefix(name, `Windows\Boot\EFI\`) {
			want[`EFI\Microsoft\Boot\`+strings.TrimPrefix(name, `Windows\Boot\EFI\`)] = "image:" + name
		}
		for _, tree := range []string{"Fonts", "Resources"} {
			if strings.HasPrefix(name, `Windows\Boot\`+tree+`\`) {
				want[`EFI\Microsoft\Boot\`+strings.TrimPrefix(name, `Windows\Boot\`)] = "image:" + name
			}
		}
	}
	want[`EFI\Microsoft\Boot\boot.stl`] = `image:Windows\Boot\EFI\boot.pnd.stl`
	files := 0
	e := filepath.WalkDir(filepath.Join(f.workspace, "base-esp"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		files++
		relative, _ := filepath.Rel(filepath.Join(f.workspace, "base-esp"), path)
		b, err := os.ReadFile(path)
		if err != nil || want[relative] == "" || string(b) != want[relative] {
			t.Fatal("wrong boot copy", relative)
		}
		return nil
	})
	if e != nil || files != len(want) {
		t.Fatal("copy inventory differs", files, len(want), e)
	}
	if entry, e := os.Stat(filepath.Join(f.workspace, `base-esp\EFI\Microsoft\Recovery`)); e != nil || !entry.IsDir() {
		t.Fatal("Recovery sibling absent")
	}
}

func TestBootGenerationSelection(t *testing.T) {
	for _, mode := range []string{"absent", "2023", "wrong issuer", "byte mismatch", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			f := newStorageFixture(t, "boot")
			if mode != "absent" {
				f.options["ex"] = true
				files := map[string]string{`Windows\Boot\EFI_EX\bootmgfw_EX.efi`: "2023-loader", `Windows\Boot\EFI_EX\en-US\bootmgfw_EX.efi.mui`: "2023-language", `Windows\Boot\EFI_EX\en-US\bootmgr_EX.efi.mui`: "unused-other-language"}
				for relative, value := range files {
					path := filepath.Join(f.workspace, "base-windows", relative)
					if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(value), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			switch mode {
			case "wrong issuer":
				f.options["refuse"] = "ex_wrong"
			case "byte mismatch":
				f.options["refuse"] = "byte_mismatch"
			case "mixed":
				f.options["refuse"] = "mixed"
			}
			b, err := f.run(baseDisk, f.data("boot"))
			if mode == "wrong issuer" {
				requireScriptStep(t, err, 61)
				return
			}
			if mode == "byte mismatch" || mode == "mixed" {
				requireScriptStep(t, err, 64)
				if bootShape(b) == nil {
					t.Fatal("missing numeric refusal")
				}
				return
			}
			var result struct {
				Generation string      `json:"boot_generation"`
				Issuers    BootIssuers `json:"boot_issuers"`
			}
			if err != nil || json.Unmarshal(b, &result) != nil || !validBootGeneration(result.Generation, result.Issuers) {
				t.Fatal("generation selection", err)
			}
			expected := "pca_2011"
			if mode == "2023" {
				expected = "uefi_ca_2023"
				for _, relative := range []string{`EFI\Boot\bootx64.efi`, `EFI\Microsoft\Boot\bootmgfw.efi`} {
					content, e := os.ReadFile(filepath.Join(f.workspace, "base-esp", relative))
					if e != nil || string(content) != "2023-loader" {
						t.Fatal("selected source copy")
					}
				}
				content, e := os.ReadFile(filepath.Join(f.workspace, "base-esp", `EFI\Microsoft\Boot\en-US\bootmgfw.efi.mui`))
				if e != nil || string(content) != "2023-language" {
					t.Fatal("EX language mapping")
				}
			}
			if result.Generation != expected {
				t.Fatal("wrong generation")
			}
		})
	}
}

func TestBootCopyRefusals(t *testing.T) {
	for _, name := range bootFixtureSources() {
		if strings.Contains(name, "EFI_EX") || strings.HasSuffix(name, "mui") || strings.HasSuffix(name, `EFI\boot.stl`) {
			continue
		}
		t.Run(name, func(t *testing.T) {
			f := newStorageFixture(t, "boot")
			if e := os.Remove(filepath.Join(f.workspace, "base-windows", name)); e != nil {
				t.Fatal(e)
			}
			_, e := f.run(baseDisk, f.data("boot"))
			requireScriptStep(t, e, 61)
		})
	}
	t.Run("link", func(t *testing.T) {
		f := newStorageFixture(t, "boot")
		target := filepath.Join(f.root, "foreign")
		if e := os.Mkdir(target, 0700); e != nil {
			t.Fatal(e)
		}
		input, _ := json.Marshal(map[string]string{"target": target, "link": filepath.Join(f.workspace, `base-windows\Windows\Boot\EFI\linked`)})
		runTestPS(t, `$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;$null=New-Item -ItemType Junction -Path $d.link -Target $d.target`, input)
		_, e := f.run(baseDisk, f.data("boot"))
		requireScriptStep(t, e, 61)
	})
	t.Run("file_bound", func(t *testing.T) {
		f := newStorageFixture(t, "boot")
		file, e := os.OpenFile(filepath.Join(f.workspace, `base-windows\Windows\Boot\EFI\oversized`), os.O_CREATE|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		e = file.Truncate(33 << 20)
		_ = file.Close()
		if e != nil {
			t.Fatal(e)
		}
		_, e = f.run(baseDisk, f.data("boot"))
		requireScriptStep(t, e, 61)
	})
}

func expectedBCDCommands(f *storageFixture) [][]string {
	loader := f.data("boot")["loader_guid"]
	commands := [][]string{
		{"/create", "{bootmgr}", "/d", "Windows Boot Manager"},
		{"/create", loader, "/d", "Windows", "/application", "osloader"},
		{"/set", "{bootmgr}", "path", `\EFI\Microsoft\Boot\bootmgfw.efi`},
		{"/set", "{bootmgr}", "locale", "en-US"},
		{"/timeout", "0"},
		{"/displayorder", loader},
		{"/default", loader},
		{"/set", loader, "path", `\Windows\system32\winload.efi`},
		{"/set", loader, "systemroot", `\Windows`},
		{"/set", loader, "locale", "en-US"},
		{"/set", loader, "nx", "OptIn"},
		{"/set", loader, "bootmenupolicy", "Standard"},
		{"/set", loader, "recoveryenabled", "No"},
		{"/set", loader, "isolatedcontext", "Yes"},
		{"/set", loader, "allowedinmemorysettings", "0x15000075"},
	}
	for i := range commands {
		commands[i] = append([]string{"/store", filepath.Join(f.workspace, `base-esp\EFI\Microsoft\Boot\BCD`)}, commands[i]...)
	}
	return append([][]string{{"/createstore", filepath.Join(f.workspace, `base-esp\EFI\Microsoft\Boot\BCD`)}}, commands...)
}

func TestBCDCommandsAndFailures(t *testing.T) {
	for fail := 0; fail <= 16; fail++ {
		t.Run(strconv.Itoa(fail), func(t *testing.T) {
			f := newStorageFixture(t, "boot")
			f.options["bcd_fail"] = fail
			b, e := f.run(baseDisk, f.data("boot"))
			if fail == 0 {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				requireScriptStep(t, e, 62)
				if shape := bootShape(b); shape == nil || !strings.Contains(shape.Error(), "command="+strconv.Itoa(fail)+" exit=17") {
					t.Fatal("command failure lacks numeric shape")
				}
			}
			raw, _ := json.Marshal(f.readState()["tool_calls"])
			var calls [][]string
			if json.Unmarshal(raw, &calls) != nil {
				t.Fatal("invalid tool calls")
			}
			count := 16
			if fail != 0 {
				count = fail
			}
			if len(calls) != count {
				t.Fatal("continued after failed BCD command")
			}
			for i, call := range calls {
				if !slices.Equal(call, expectedBCDCommands(f)[i]) || (i != 0 && call[0] != "/store") || slices.Contains(call, "{fwbootmgr}") || slices.Contains(call, "inherit") || slices.Contains(call, "device") || slices.Contains(call, "osdevice") {
					t.Fatal("unsafe or wrong BCD argument array", i)
				}
			}
			if _, e := f.cleanup(); e != nil {
				t.Fatal("cleanup after BCD command", e)
			}
		})
	}
}

func TestBCDWriteFailureCleanup(t *testing.T) {
	for code := 1; code <= 10; code++ {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			f := newStorageFixture(t, "boot")
			f.options["write"] = code
			b, err := f.run(baseDisk, f.data("boot"))
			requireScriptStep(t, err, 63)
			if shape := bootShape(b); shape == nil || shape.Error() != "offline BCD device write refused: code="+strconv.Itoa(code) {
				t.Fatal("device write failure lost numeric shape")
			}
			if _, err := f.cleanup(); err != nil {
				t.Fatal("write failure cleanup", err)
			}
		})
	}
}

func TestBootHasNoTemporaryLetterPlan(t *testing.T) {
	r := &record{StorageIntents: fixtureCleanupIntents()}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{"temporary_letter", "windows_temporary_letter", "retained_letters"} {
		if strings.Contains(string(b), removed) || strings.Contains(r.scriptData()["storage_intents"], removed) {
			t.Fatal("removed letter state retained")
		}
		if _, exists := r.scriptData()[removed]; exists {
			t.Fatal("removed letter script input retained")
		}
	}
	for _, script := range []string{baseDisk, bootHelpers, detachDisk} {
		for _, removed := range []string{"MountedDevices", "Get-PSDrive", "partition=", "$data.letter", "$data.windows_letter"} {
			if strings.Contains(script, removed) {
				t.Fatal("boot/cleanup retains a letter operation")
			}
		}
	}
}

func TestBCDVerificationFailureCleanup(t *testing.T) {
	for code := 1; code <= 27; code++ {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			f := newStorageFixture(t, "boot")
			f.options["verify"] = code
			b, e := f.run(baseDisk, f.data("boot"))
			requireScriptStep(t, e, 65)
			if shape := bootShape(b); shape == nil || shape.Error() != "offline BCD refused: code="+strconv.Itoa(code) {
				t.Fatal("missing numeric verification shape")
			}
			if _, e := f.cleanup(); e != nil {
				t.Fatal("verification failure cleanup", e)
			}
		})
	}
}
