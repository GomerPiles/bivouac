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
		`Windows\System32\config\BCD-Template`, `Windows\System32\winload.efi`,
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

func assertFixtureLettersRemoved(t *testing.T, f *storageFixture) {
	t.Helper()
	for _, key := range []string{"letter", "windows_letter"} {
		if f.readState()[key] != false {
			t.Fatal("temporary letter survived", key)
		}
	}
}

func TestBootCopySet(t *testing.T) {
	f := newStorageFixture(t, "boot")
	if _, e := f.run(baseDisk, f.data("boot")); e != nil {
		t.Fatal(e)
	}
	want := map[string]string{
		`EFI\Boot\bootx64.efi`:   `Windows\Boot\EFI\bootmgfw.efi`,
		`EFI\Microsoft\Boot\BCD`: `Windows\System32\config\BCD-Template`,
	}
	for _, name := range bootFixtureSources() {
		if strings.HasPrefix(name, `Windows\Boot\EFI\`) {
			want[`EFI\Microsoft\Boot\`+strings.TrimPrefix(name, `Windows\Boot\EFI\`)] = name
		}
		for _, tree := range []string{"Fonts", "Resources"} {
			if strings.HasPrefix(name, `Windows\Boot\`+tree+`\`) {
				want[`EFI\Microsoft\Boot\`+strings.TrimPrefix(name, `Windows\Boot\`)] = name
			}
		}
	}
	want[`EFI\Microsoft\Boot\boot.stl`] = `Windows\Boot\EFI\boot.pnd.stl`
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
		if err != nil || want[relative] == "" || string(b) != "image:"+want[relative] {
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
	assertFixtureLettersRemoved(t, f)
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
			requireScriptStep(t, e, 62)
			assertFixtureLettersRemoved(t, f)
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
		requireScriptStep(t, e, 62)
		assertFixtureLettersRemoved(t, f)
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
		requireScriptStep(t, e, 62)
		assertFixtureLettersRemoved(t, f)
	})
}

func expectedBCDCommands(f *storageFixture) [][]string {
	loader := f.data("boot")["loader_guid"]
	commands := [][]string{
		{"/create", loader, "/d", "Windows", "/application", "osloader"},
		{"/set", "{bootmgr}", "device", "partition=Z:"},
		{"/set", "{bootmgr}", "path", `\EFI\Microsoft\Boot\bootmgfw.efi`},
		{"/set", "{bootmgr}", "locale", "en-US"},
		{"/set", "{bootmgr}", "timeout", "0"},
		{"/set", "{bootmgr}", "displayorder", loader},
		{"/set", "{bootmgr}", "default", loader},
		{"/set", loader, "device", "partition=Y:"},
		{"/set", loader, "osdevice", "partition=Y:"},
		{"/set", loader, "path", `\Windows\system32\winload.efi`},
		{"/set", loader, "systemroot", `\Windows`},
		{"/set", loader, "locale", "en-US"},
		{"/set", loader, "inherit", "{bootloadersettings}"},
		{"/set", loader, "nx", "OptIn"},
		{"/set", loader, "bootmenupolicy", "Standard"},
		{"/set", loader, "recoveryenabled", "No"},
		{"/delete", "{9f25ee7a-e7b7-11db-94b5-f7e662935912}"},
		{"/delete", "{77777777-7777-4777-8777-777777777777}"},
		{"/delete", "{88888888-8888-4888-8888-888888888888}"},
		{"/delete", "{99999999-9999-4999-8999-999999999999}"},
	}
	for i := range commands {
		commands[i] = append([]string{"/store", filepath.Join(f.workspace, `base-esp\EFI\Microsoft\Boot\BCD`)}, commands[i]...)
	}
	return commands
}

func TestBCDCommandsAndFailures(t *testing.T) {
	for fail := 0; fail <= 20; fail++ {
		t.Run(strconv.Itoa(fail), func(t *testing.T) {
			f := newStorageFixture(t, "boot")
			f.options["bcd_fail"] = fail
			b, e := f.run(baseDisk, f.data("boot"))
			if fail == 0 {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				requireScriptStep(t, e, 63)
				if shape := bootShape(b); shape == nil || !strings.Contains(shape.Error(), "command="+strconv.Itoa(fail)+" exit=17") {
					t.Fatal("command failure lacks numeric shape")
				}
			}
			raw, _ := json.Marshal(f.readState()["tool_calls"])
			var calls [][]string
			if json.Unmarshal(raw, &calls) != nil {
				t.Fatal("invalid tool calls")
			}
			count := 20
			if fail != 0 {
				count = fail
			}
			if len(calls) != count {
				t.Fatal("continued after failed BCD command")
			}
			for i, call := range calls {
				if !slices.Equal(call, expectedBCDCommands(f)[i]) || call[0] != "/store" || slices.Contains(call, "{fwbootmgr}") {
					t.Fatal("unsafe or wrong BCD argument array", i)
				}
			}
			assertFixtureLettersRemoved(t, f)
			if _, e := f.cleanup(); e != nil {
				t.Fatal("cleanup after BCD command", e)
			}
		})
	}
}

func TestBCDVerificationFailureCleanup(t *testing.T) {
	for code := 1; code <= 12; code++ {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			f := newStorageFixture(t, "boot")
			f.options["verify"] = code
			b, e := f.run(baseDisk, f.data("boot"))
			requireScriptStep(t, e, 65)
			if shape := bootShape(b); shape == nil || shape.Error() != "offline BCD refused: code="+strconv.Itoa(code) {
				t.Fatal("missing numeric verification shape")
			}
			assertFixtureLettersRemoved(t, f)
			if _, e := f.cleanup(); e != nil {
				t.Fatal("verification failure cleanup", e)
			}
		})
	}
}

func TestCleanupLetterPartitionGUIDRefusals(t *testing.T) {
	for _, refuse := range []string{"partition_guid", "windows_guid"} {
		t.Run(refuse, func(t *testing.T) {
			f := newStorageFixture(t, "boot")
			f.state["letter"], f.state["windows_letter"] = true, true
			writeFixtureJSON(t, f.statePath, f.state)
			f.options["refuse"] = refuse
			_, e := f.cleanup()
			requireScriptStep(t, e, 1)
			name := "remove_letter"
			if refuse == "windows_guid" {
				name = "remove_windows_letter"
			}
			if slices.Contains(f.trace(), name) {
				t.Fatal("unproven letter ownership was removed")
			}
		})
	}
}
