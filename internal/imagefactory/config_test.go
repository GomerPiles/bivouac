package imagefactory

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func testConfig() Config {
	h := strings.Repeat("a", 64)
	c := Config{ISO: `D:\Media\base\install.iso`, ISOSHA256: h, EditionID: "Professional", DiskGB: 127, GuestUser: "imageuser", CPU: 4, MemoryMB: 8192, ImageRoot: `D:\Images`, TimeoutSeconds: 900, RenderProbe: PinnedFile{Source: `D:\Assets\render.exe`, SHA256: h}, Drivers: []string{`C:\Windows\System32\DriverStore\FileRepository\display.inf_amd64_example`}}
	c.SetupAssets = []Asset{{Name: "RUNNER.ZIP", PinnedFile: PinnedFile{Source: `D:\Assets\runner.zip`, SHA256: h}}}
	return c
}

func TestConfigAllowsAutomaticGPUDiscovery(t *testing.T) {
	c := testConfig()
	c.Drivers = nil
	if err := c.Validate(); err != nil {
		t.Fatal("omitted drivers should discover the active host packages", err)
	}
}
func TestConfig(t *testing.T) {
	c := testConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{`D:\IMAGES~1`, `D:\Media\base\images`} {
		bad := testConfig()
		bad.ImageRoot = path
		if bad.Validate() == nil {
			t.Fatal("short alias or template child accepted")
		}
	}
	for name, mutate := range map[string]func(*Config){
		"pin": func(c *Config) { c.ISOSHA256 = "bad" }, "relative": func(c *Config) { c.ISO = `disk.vhdx` }, "source inside output": func(c *Config) { c.ISO = `D:\Images\disk.vhdx` }, "root overlaps": func(c *Config) { c.ImageRoot = `D:\Media` }, "unc": func(c *Config) { c.ImageRoot = `\\server\images` }, "root alias": func(c *Config) { c.ImageRoot = `D:\Images.` }, "dot segment": func(c *Config) { c.ImageRoot = `D:\Images\..\Templates` }, "device": func(c *Config) { c.ImageRoot = `D:\CON` }, "cpu": func(c *Config) { c.CPU = 5 }, "memory": func(c *Config) { c.MemoryMB = 8193 }, "timeout": func(c *Config) { c.TimeoutSeconds = 1 }, "user": func(c *Config) { c.GuestUser = "user\n" }, "template": func(c *Config) { c.EditionID = "../edition" }, "disk small": func(c *Config) { c.DiskGB = 63 }, "disk large": func(c *Config) { c.DiskGB = 257 }, "index": func(c *Config) { c.ImageIndex = 129 }, "asset pin": func(c *Config) { c.SetupAssets[0].SHA256 = "" }, "asset duplicate": func(c *Config) { c.SetupAssets = append(c.SetupAssets, c.SetupAssets[0]) }, "asset name": func(c *Config) { c.SetupAssets[0].Name = "../agent" }, "drivers too many": func(c *Config) {
			for range 9 {
				c.Drivers = append(c.Drivers, c.Drivers[0])
			}
		}, "drivers duplicate": func(c *Config) { c.Drivers = append(c.Drivers, c.Drivers[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			c := testConfig()
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	b, _ := json.Marshal(c)
	var data map[string]any
	_ = json.Unmarshal(b, &data)
	delete(data, "edition_id")
	delete(data, "disk_gb")
	delete(data, "cpu")
	delete(data, "memory_mb")
	delete(data, "timeout_seconds")
	b, _ = json.Marshal(data)
	got, err := DecodeConfig(strings.NewReader(string(b)))
	if err != nil || got.CPU != 4 || got.MemoryMB != 8192 || got.TimeoutSeconds != 900 || got.EditionID != "Professional" || got.DiskGB != 127 {
		t.Fatal("defaults", err)
	}
	for _, bad := range []string{string(b) + "{}", `{"unexpected":"arbitrary-input"}`, `{"source":"legacy"}`, `{"source_sha256":"legacy"}`, `{"expected_template":"legacy"}`, strings.Repeat("x", 65537)} {
		if _, err := DecodeConfig(strings.NewReader(bad)); err == nil || strings.Contains(err.Error(), "arbitrary-input") {
			t.Fatal("invalid input or error echo")
		}
	}
	c.SetupAssets = nil
	if c.Validate() == nil {
		t.Fatal("missing runner archive accepted")
	}
}
func TestGuestNameAndPins(t *testing.T) {
	n, err := GuestName("b05ac3dfb3dba7ffe720d39021b71ac5")
	if err != nil || n != "bivouac-wbnmhxy" {
		t.Fatalf("name %q %v", n, err)
	}
	for _, id := range []string{"", strings.Repeat("A", 32), strings.Repeat("0", 30)} {
		if _, err := GuestName(id); err == nil {
			t.Fatal("invalid ID accepted")
		}
	}
	if hashBytes([]byte("abc")) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("hash")
	}
}
func TestInspectionFailsClosed(t *testing.T) {
	good := Inspection{SystemSetupInProgress: 1, OOBEInProgress: 1, SetupPhase: 4, ImageStateKind: "generalized_to_oobe", UnattendPointerKind: "absent", AnswerDirectoryEmpty: true, PantherAnswerPresent: true}
	if !good.Generalized() {
		t.Fatal("baseline rejected")
	}
	for _, mutate := range []func(*Inspection){func(i *Inspection) { i.SystemHiveError = 5 }, func(i *Inspection) { i.SoftwareHiveError = 2 }, func(i *Inspection) { i.SystemSetupInProgress = 0 }, func(i *Inspection) { i.OOBEInProgress = 0 }, func(i *Inspection) { i.ImageStateKind = "specialized" }, func(i *Inspection) { i.UnattendPointerKind = "present_or_unknown" }, func(i *Inspection) { i.AnswerDirectoryEmpty = false }} {
		bad := good
		mutate(&bad)
		if bad.Generalized() {
			t.Fatal("unsafe inspection accepted")
		}
	}
	if (Inspection{}).Generalized() {
		t.Fatal("missing facts accepted")
	}
}
func TestAnswerAndMediaScripts(t *testing.T) {
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	placeholder := hex.EncodeToString(random[:])
	defer clear(random[:])
	answer := unattended("bivouac-aaaaaaa", "imageuser", placeholder)
	d := xml.NewDecoder(strings.NewReader(answer))
	var values []string
	for {
		token, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if chars, ok := token.(xml.CharData); ok {
			values = append(values, string(chars))
		}
	}
	if !strings.Contains(strings.Join(values, "|"), placeholder) || !strings.Contains(answer, `pass="specialize"`) || !strings.Contains(answer, `pass="oobeSystem"`) || !strings.Contains(answer, `C:\Windows\Panther\Unattend\specialize.ps1`) {
		t.Fatal("answer contract")
	}
	if !strings.Contains(xmlText("<&"), "&lt;&amp;") {
		t.Fatal("XML escaping")
	}
	files := mediaScripts()
	if files["SETUP.PS1"] != videoFacts+guestVideo+guestSetup {
		t.Fatal("setup media lacks video helpers")
	}
	for _, name := range []string{"SETUP.PS1", "HCSRUNNER.PS1", "HCSVALIDATE.PS1", "HCSSANITIZE.PS1", "HCSLOGON.PS1", "HCSCHECK.PS1"} {
		if files[name] == "" {
			t.Fatal("missing setup script", name)
		}
	}
	for _, content := range files {
		if strings.Contains(content, placeholder) {
			t.Fatal("private setup value in public media script")
		}
	}
	if strings.Contains(guestValidate, "bootTimings") || strings.Contains(imageSanitize, "BootCheckpoint") || strings.Contains(strings.Join(values, "|"), "Set-TimeZone") {
		t.Fatal("out of scope instrumentation")
	}
}
func TestScriptConstantsMatchLF(t *testing.T) {
	b, err := os.ReadFile("offline_files.ps1")
	if err != nil || string(b) != offlineFiles || strings.ContainsRune(offlineFiles, '\r') {
		t.Fatal("regenerate LF offline facts script")
	}
	for name, content := range map[string]string{"embedded_signatures.ps1": embeddedSignatures, "offline_encryption.ps1": offlineEncryption, "boot_helpers.ps1": bootHelpers, "base_disk.ps1": baseDisk, "offline_payload.ps1": offlinePayload, "make_iso.ps1": makeISO, "runner_extract.ps1": runnerExtract, "guest_setup.ps1": guestSetup, "guest_video.ps1": guestVideo, "video_facts.ps1": videoFacts, "stage_setup.ps1": stageSetup, "guest_specialize.ps1": guestSpecialize, "guest_validate.ps1": guestValidate, "image_sanitize.ps1": imageSanitize, "autologon_secret.ps1": autologonSecret, "inspect_disk.ps1": inspectDisk, "detach_disk.ps1": detachDisk, "runner_check.ps1": runnerCheck} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != content || strings.ContainsRune(content, '\r') {
			t.Fatal("regenerate LF script", name)
		}
	}
}
func TestManifestPublicFields(t *testing.T) {
	m := Manifest{BuildID: strings.Repeat("a", 32), GuestName: "bivouac-aaaaaaa", GuestUser: "imageuser", Media: MediaRecord{ISOSHA256: strings.Repeat("b", 64)}, Output: `D:\Images\disk.vhdx`, SHA256: strings.Repeat("c", 64), ProbeSHA256: hashBytes([]byte(guestValidate)), ValidationSHA256: hashBytes([]byte(guestValidate)), AutologonSHA256: hashBytes([]byte(autologonSecret)), Assets: map[string]string{"AGENT.EXE": strings.Repeat("d", 64)}}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.Unmarshal(b, &fields) != nil {
		t.Fatal("manifest JSON")
	}
	for _, required := range []string{"prevent_device_encryption", "agent_sha256", "windows_contract", "autologon_account_matches", "agent_task", "runner_task", "build_id", "guest_name", "guest_user", "media", "security", "output", "size", "sha256", "probe_sha256", "validation_sha256", "autologon_sha256", "assets", "drivers", "vcs_revision", "started", "ended", "phase_ms"} {
		if _, ok := fields[required]; !ok {
			t.Fatal("missing", required)
		}
	}
	for _, removed := range []string{"source", "source_sha256", "template"} {
		if _, ok := fields[removed]; ok {
			t.Fatal("template field survived", removed)
		}
	}
	media := fields["media"].(map[string]any)
	for _, required := range []string{"iso_sha256", "install_kind", "image", "host_dism_version", "host_bcdedit_version", "boot_method", "loader_guid", "bcd_verified", "boot_issuers", "boot_generation", "winre", "layout"} {
		if _, ok := media[required]; !ok {
			t.Fatal("missing media field", required)
		}
	}
	layout := media["layout"].(map[string]any)
	for _, required := range []string{"disk_guid", "esp_guid", "msr_guid", "windows_guid"} {
		if _, ok := layout[required]; !ok {
			t.Fatal("missing layout identity", required)
		}
	}
	for key := range fields {
		for _, secret := range []string{"password", "private_key", "jit", "token", "unattend"} {
			if strings.Contains(key, secret) {
				t.Fatal("secret field in manifest")
			}
		}
	}
}
func TestCleanupOrdering(t *testing.T) {
	for _, test := range []struct {
		name           string
		absent, detach bool
		want           []string
	}{
		{"settled", true, true, []string{"terminate", "absence", "detach", "remove"}},
		{"unknown absence", false, true, []string{"terminate", "absence"}},
		{"mounted", true, false, []string{"terminate", "absence", "detach"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			err := cleanupOwned(func() error { calls = append(calls, "terminate"); return errors.New("lost response") }, func() error {
				calls = append(calls, "absence")
				if !test.absent {
					return errors.New("unknown")
				}
				return nil
			}, func() error {
				calls = append(calls, "detach")
				if !test.detach {
					return errors.New("mounted")
				}
				return nil
			}, func() error { calls = append(calls, "remove"); return nil })
			if !reflect.DeepEqual(calls, test.want) || (err == nil) != (test.absent && test.detach) {
				t.Fatalf("cleanup ordering: %v", calls)
			}
		})
	}
}

func TestEligibleRefusesTemplateRunnerState(t *testing.T) {
	good := Inspection{SystemSetupInProgress: 1, OOBEInProgress: 1, ImageStateKind: "generalized_to_oobe", UnattendPointerKind: "absent", AnswerDirectoryEmpty: true, RunnerState: "absent"}
	if !good.Eligible() {
		t.Fatal("clean image rejected")
	}
	for _, state := range []string{"unconfigured", "residue", "configured"} {
		bad := good
		bad.RunnerState = state
		if bad.Eligible() {
			t.Fatal("runner state accepted", state)
		}
	}
}

func TestExitTypeNameAllowList(t *testing.T) {
	for in, want := range map[string]string{"GracefulExit": "GracefulExit", "UnexpectedExit": "UnexpectedExit", "ForcedExit": "ForcedExit", "": "other", "guest text": "other"} {
		if got := exitTypeName(in); got != want {
			t.Fatalf("%q: got %q", in, got)
		}
	}
}
