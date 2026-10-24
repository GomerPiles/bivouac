//go:build windows

package imagefactory

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio/wim"
)

// This is a read-only alternative to applying/mounting an image: extract only
// the pristine media's two registry hives to a test temp directory and query
// them through offreg. No registry load, disk attach, DISM, or HCS call occurs.
func TestReferenceOfflineState(t *testing.T) {
	path := os.Getenv("BIVOUAC_TEST_ISO")
	if path == "" {
		t.Skip("set BIVOUAC_TEST_ISO for reference offline gates")
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = f.Close() }()
	info, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	v := udfVolume{r: f, size: info.Size()}
	a, e := v.open()
	if e != nil {
		t.Fatal(e)
	}
	dirs, e := v.directory(a)
	if e != nil {
		t.Fatal(e)
	}
	sources, e := v.directory(dirs["sources"])
	if e != nil {
		t.Fatal(e)
	}
	install, _, e := v.file(sources["install.wim"])
	if e != nil {
		t.Fatal(e)
	}
	wr, e := wim.NewReader(install)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = wr.Close() }()
	if len(wr.Image) < 6 {
		t.Fatal("reference Professional index absent")
	}
	root, e := wr.Image[5].Open()
	if e != nil {
		t.Fatal(e)
	}
	find := func(relative string) *wim.File {
		current := root
		for _, name := range strings.Split(relative, `\`) {
			entries, err := current.Readdir()
			if err != nil {
				t.Fatal("WIM directory read failed")
			}
			current = nil
			for _, entry := range entries {
				if strings.EqualFold(entry.Name, name) {
					current = entry
					break
				}
			}
			if current == nil {
				return nil
			}
		}
		return current
	}
	for _, path := range []string{`actions-runner`, `Program Files\Bivouac`, `ProgramData\Bivouac\Guest`, `Windows\System32\Tasks\bivouac-guest-agent`, `Windows\Panther\Unattend`} {
		entry := find(path)
		if entry != nil {
			if path != `Windows\Panther\Unattend` {
				t.Fatal("reference clean-install path gate refused")
			}
			entries, err := entry.Readdir()
			if err != nil || len(entries) != 0 {
				t.Fatal("reference answer directory not empty")
			}
		}
	}
	temp := t.TempDir()
	for _, name := range []string{"SYSTEM", "SOFTWARE", "BCD-Template", "bootmgfw.efi"} {
		relative := `Windows\System32\config\` + name
		if name == "bootmgfw.efi" {
			relative = `Windows\Boot\EFI\bootmgfw.efi`
		}
		entry := find(relative)
		if entry == nil || entry.Size < 1 || entry.Size > 256<<20 {
			t.Fatal("reference hive absent or oversized")
		}
		in, err := entry.Open()
		if err != nil {
			t.Fatal("WIM hive open failed")
		}
		out, err := os.OpenFile(filepath.Join(temp, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			_ = in.Close()
			t.Fatal(err)
		}
		n, err := io.Copy(out, io.LimitReader(in, 256<<20))
		_ = in.Close()
		_ = out.Close()
		if err != nil || n != entry.Size {
			t.Fatal("WIM hive extraction failed")
		}
	}
	start := strings.Index(inspectDisk, "@\"\n") + 3
	end := strings.Index(inspectDisk[start:], "\n\"@") + start
	script := bootHelpers + "\n" + `$ErrorActionPreference='Stop';$data=[Console]::In.ReadToEnd()|ConvertFrom-Json;$null=Add-Type -TypeDefinition @"` + "\n" + inspectDisk[start:end] + "\n\"@\n" + `
 $signature=Get-AuthenticodeSignature -LiteralPath (Join-Path $data.root 'bootmgfw.efi')
 $f=@{boot_signature_valid=($signature.Status -eq 'Valid');boot_signer_2011=($signature.SignerCertificate.Issuer -like '*Microsoft Windows Production PCA 2011*');boot_signer_2023=($signature.SignerCertificate.Issuer -like '*Windows UEFI CA 2023*');runner_state='absent';answer_directory_empty=$true};$h=[IntPtr]::Zero
 $f.system_hive_error=[FactoryInspection]::OROpenHive((Join-Path $data.root 'SYSTEM'),[ref]$h)
 if($f.system_hive_error -eq 0){try{$f.system_setup_in_progress=[FactoryInspection]::Number($h,'Setup','SystemSetupInProgress');$f.oobe_in_progress=[FactoryInspection]::Number($h,'Setup','OOBEInProgress');$f.setup_phase=[FactoryInspection]::Number($h,'Setup','SetupPhase');$f.unattend_pointer_kind=[FactoryInspection]::Pointer($h)}finally{[void][FactoryInspection]::ORCloseHive($h)}}
 $f.software_hive_error=[FactoryInspection]::OROpenHive((Join-Path $data.root 'SOFTWARE'),[ref]$h)
 if($f.software_hive_error -eq 0){try{$f.image_state_kind=[FactoryInspection]::State($h)}finally{[void][FactoryInspection]::ORCloseHive($h)}}
 $loaders=@(Get-TemplateLoaders (Join-Path $data.root 'BCD-Template'))
 $f.boot_template_valid=($loaders.Count -gt 0);$f.boot_template_loaders=$loaders.Count
 [Console]::Out.Write(($f|ConvertTo-Json -Compress))`
	input, _ := json.Marshal(map[string]string{"root": temp})
	output := runTestPS(t, script, input)
	var facts Inspection
	if json.Unmarshal([]byte(output), &facts) != nil {
		t.Fatal("invalid offline reference facts")
	}
	var boot struct {
		Valid    bool `json:"boot_signature_valid"`
		Legacy   bool `json:"boot_signer_2011"`
		Modern   bool `json:"boot_signer_2023"`
		Template bool `json:"boot_template_valid"`
	}
	if json.Unmarshal([]byte(output), &boot) != nil || !boot.Valid || !boot.Legacy || boot.Modern || !boot.Template {
		t.Fatal("reference boot signing requires design review")
	}
	t.Log(output)
	if !facts.Eligible() {
		t.Fatal("reference media contradicts inspection gate")
	}
}
