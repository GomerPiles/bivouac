//go:build windows

package hcsspike

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func setupFixture(c Config) []SetupAsset {
	var assets []SetupAsset
	for _, name := range []string{"APPSANDBOX-AGENT.EXE", "APPSANDBOX-INPUT.EXE", "APPSANDBOX-DISPLAYS.EXE", "APPSANDBOXVDD.DLL", "APPSANDBOXVDD.INF", "APPSANDBOXVDD.CAT", "DEVCON.EXE"} {
		assets = append(assets, SetupAsset{Name: name, PinnedFile: PinnedFile{Source: `C:\Fixture\` + name, SHA256: c.BaselineSHA256}})
	}
	return assets
}
func TestSetupAssetNamesAndPinsAreBounded(t *testing.T) {
	c := exampleConfig()
	c.SetupAssets = setupFixture(c)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.SetupAssets[0].Name = `..\unattend.xml` },
		func(c *Config) { c.SetupAssets[0].SHA256 = "invalid" },
		func(c *Config) { c.SetupAssets = append(c.SetupAssets, c.SetupAssets[0]) },
		func(c *Config) { c.SetupAssets = c.SetupAssets[:1] },
	} {
		bad := c
		bad.SetupAssets = append([]SetupAsset(nil), c.SetupAssets...)
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("unsafe/incomplete assets accepted")
		}
	}
	plan, err := Plan(c)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(plan)
	if !bytes.Contains(b, []byte("setup.iso")) {
		t.Fatal("setup media not attached")
	}
}
func TestUnattendEscapesDataAndDoesNotPutSecretInConfig(t *testing.T) {
	c := exampleConfig()
	c.GuestUser = `guest<&"`
	document := unattended(c, "synthetic<&")
	d := xml.NewDecoder(strings.NewReader(document))
	for {
		_, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal("invalid unattended XML")
		}
	}
	if !strings.Contains(document, "guest&lt;&amp;&#34;") {
		t.Fatal("account data not XML escaped")
	}
	data, _ := json.Marshal(c)
	if bytes.Contains(data, []byte("synthetic")) {
		t.Fatal("setup secret persisted in config")
	}
}
func TestISOBuilderUsesMemoryAnswerFile(t *testing.T) {
	dir := t.TempDir()
	assets := filepath.Join(dir, "assets")
	if err := os.Mkdir(assets, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assets, "SETUP.PS1"), []byte("exit 0"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"HCSRENDER.EXE": []byte("synthetic public probe"), "HCSVALIDATE.PS1": []byte(guestValidate)} {
		if err := os.WriteFile(filepath.Join(assets, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	dest := filepath.Join(dir, "setup.iso")
	input, _ := json.Marshal(map[string]string{"assets": assets, "destination": dest, "unattend": "<unattend />"})
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedPowerShell(makeISO))
	cmd.Stdin = bytes.NewReader(input)
	if err = cmd.Run(); err != nil {
		t.Fatal("memory-backed ISO fixture failed")
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 32775 || string(data[32769:32774]) != "CD001" {
		t.Fatal("ISO descriptor missing")
	}
	if !slices.Contains(jolietRootNames(t, data), "Autounattend.xml") {
		t.Fatalf("Windows removable-media answer filename missing: %q", jolietRootNames(t, data))
	}
	for _, name := range []string{"HCSRENDER.EXE", "HCSVALIDATE.PS1"} {
		if !slices.Contains(jolietRootNames(t, data), name) {
			t.Fatal("public validation asset missing from media")
		}
	}
	entries, err := os.ReadDir(assets)
	if err != nil || len(entries) != 3 {
		t.Fatal("answer file was written into host staging")
	}
}
func TestRenderReportRejectsPartialAndSoftwareResults(t *testing.T) {
	good := renderResult{GuestReady: true, DesktopReady: true, HardwareD3D11: true, Presented: true, PixelReadback: true, Stage: 7, AdapterCount: 2, HardwareAdapterCount: 1, VendorID: 0x1002, DeviceID: 1}
	data, _ := json.Marshal(good)
	if _, err := validateRenderReport(data); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*renderResult){func(r *renderResult) { r.GuestReady = false }, func(r *renderResult) { r.DesktopReady = false }, func(r *renderResult) { r.PixelReadback = false }, func(r *renderResult) { r.Presented = false }, func(r *renderResult) { r.HardwareD3D11 = false }, func(r *renderResult) { r.HRESULT = 1 }, func(r *renderResult) { r.AdapterCount = 33 }, func(r *renderResult) { r.HardwareAdapterCount = 0 }, func(r *renderResult) { r.HardwareAdapterCount = 3 }, func(r *renderResult) { r.Stage = 6 }, func(r *renderResult) { r.VendorID = 0x1414; r.DeviceID = 0x8c }} {
		bad := good
		mutate(&bad)
		data, _ := json.Marshal(bad)
		if _, err := validateRenderReport(data); err == nil {
			t.Fatal("incomplete/software rendering accepted")
		}
	}
	for _, bad := range []string{`{"guest_ready":"true"}`, `{} {}`, `{"arbitrary":"guest text"}`} {
		if _, err := validateRenderReport([]byte(bad)); err == nil {
			t.Fatal("malformed guest report accepted")
		}
	}
	var out boundedOutput
	if _, err := out.Write(make([]byte, 4097)); err == nil {
		t.Fatal("unbounded output accepted")
	}
}

// Inspect the real ISO directory, rather than merely searching script source.
func jolietRootNames(t *testing.T, data []byte) []string {
	t.Helper()
	for offset := 16 * 2048; offset+2048 <= len(data); offset += 2048 {
		sector := data[offset : offset+2048]
		if sector[0] == 255 {
			break
		}
		if sector[0] != 2 || string(sector[1:6]) != "CD001" {
			continue
		}
		start := int(binary.LittleEndian.Uint32(sector[158:162])) * 2048
		size := int(binary.LittleEndian.Uint32(sector[166:170]))
		if start < 0 || size <= 0 || start > len(data) || size > len(data)-start {
			t.Fatal("invalid Joliet directory extent")
		}
		var names []string
		for pos := start; pos < start+size; {
			length := int(data[pos])
			if length == 0 {
				pos = (pos/2048 + 1) * 2048
				continue
			}
			if length < 34 || length > start+size-pos {
				t.Fatal("invalid Joliet record")
			}
			record := data[pos : pos+length]
			n := int(record[32])
			if n > len(record)-33 {
				t.Fatal("invalid Joliet filename")
			}
			if n%2 == 0 {
				words := make([]uint16, n/2)
				for i := range words {
					words[i] = binary.BigEndian.Uint16(record[33+i*2:])
				}
				names = append(names, strings.TrimSuffix(string(utf16.Decode(words)), ";1"))
			}
			pos += length
		}
		return names
	}
	t.Fatal("Joliet descriptor missing")
	return nil
}

func TestEmptySetupAssetsHaveStableJournalRoundTrip(t *testing.T) {
	c := exampleConfig()
	data, _ := json.Marshal(c)
	document := strings.TrimSuffix(string(data), "}") + `,"setup_assets":[]}`
	decoded, err := DecodeConfig(strings.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SetupAssets != nil {
		t.Fatal("empty asset slice differs after journal round trip")
	}
}

func TestOfflineStagingGuardCompilesAndRejectsMissingHive(t *testing.T) {
	if err := windows.NewLazySystemDLL("offreg.dll").NewProc("OROpenHive").Find(); err != nil {
		t.Skip("Windows offline registry library unavailable")
	}
	_, source, found := strings.Cut(stageSetup, "Add-Type -TypeDefinition @\"\n")
	if !found {
		t.Fatal("offline API source missing")
	}
	source, _, found = strings.Cut(source, "\n\"@")
	if !found {
		t.Fatal("offline API source terminator missing")
	}
	script := "Add-Type -TypeDefinition @\"\n" + source + "\n\"@\n$data=[Console]::In.ReadToEnd() | ConvertFrom-Json;if([SpikeOfflineAnswer]::NoExplicitAnswer($data.path)){exit 1};exit 0"
	path := filepath.Join(t.TempDir(), "absent.hive")
	data, _ := json.Marshal(map[string]string{"path": path})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := runPrivateSetup(ctx, script, data); err != nil {
		t.Fatal("offline guard failed to compile or accepted a missing hive")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("offline reader created a hive")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		err := runPrivateSetup(ctx, stageSetup, []byte("invalid-json"))
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 10 {
			t.Fatal("ordinary token reached offline staging")
		}
	}
}

func TestOfflineAnswerDirectoryGuardDoesNotReplaceContents(t *testing.T) {
	_, function, found := strings.Cut(stageSetup, "function Assert-EmptyAnswerDirectory")
	if !found {
		t.Fatal("answer directory guard missing")
	}
	function, _, found = strings.Cut(function, "\ntry {")
	if !found {
		t.Fatal("answer directory guard terminator missing")
	}
	guard := "$ErrorActionPreference='Stop';function Assert-EmptyAnswerDirectory" + function
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0700); err != nil {
		t.Fatal(err)
	}
	occupied := filepath.Join(dir, "occupied")
	if err := os.Mkdir(occupied, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(occupied, "unattend.xml")
	if err := os.WriteFile(sentinel, []byte("synthetic preserved answer"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path     string
		accepted bool
	}{{filepath.Join(dir, "absent"), true}, {empty, true}, {occupied, false}, {sentinel, false}} {
		input, _ := json.Marshal(map[string]string{"path": item.path})
		script := guard + "\n$data=[Console]::In.ReadToEnd() | ConvertFrom-Json;try{Assert-EmptyAnswerDirectory $data.path;exit 0}catch{exit 1}"
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := runPrivateSetup(ctx, script, input)
		cancel()
		if (err == nil) != item.accepted {
			t.Fatal("answer directory guard accepted unsafe contents or refused empty directory")
		}
	}
	content, err := os.ReadFile(sentinel)
	if err != nil || string(content) != "synthetic preserved answer" {
		t.Fatal("existing answer changed")
	}
}

func TestOfflineDirectoryProtectionChangesOnlyDACL(t *testing.T) {
	_, source, found := strings.Cut(stageSetup, "Add-Type -TypeDefinition @\"\n")
	if !found {
		t.Fatal("offline API source missing")
	}
	source, _, found = strings.Cut(source, "\n\"@")
	if !found {
		t.Fatal("offline API source terminator missing")
	}
	dir := filepath.Join(t.TempDir(), "protected")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]string{"path": dir, "sddl": "D:P(A;OICI;FA;;;" + tokenUser.User.Sid.String() + ")"})
	script := "Add-Type -TypeDefinition @\"\n" + source + "\n\"@\n$data=[Console]::In.ReadToEnd() | ConvertFrom-Json;if([SpikeOfflineAnswer]::ProtectDirectory($data.path,$data.sddl) -ne 0){exit 1};if(!(Get-Acl -LiteralPath $data.path).AreAccessRulesProtected){exit 2};exit 0"
	before, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := runPrivateSetup(ctx, script, input); err != nil {
		t.Fatal("DACL-only protection failed")
	}
	after, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION)
	if err != nil || before.String() != after.String() {
		t.Fatal("DACL update changed owner/group")
	}
	if err := os.WriteFile(filepath.Join(dir, "sentinel"), []byte("synthetic"), 0600); err != nil {
		t.Fatal("DACL lost intended access")
	}
}

func TestUnattendCommandsRespectWindowsSchemaLengths(t *testing.T) {
	d := xml.NewDecoder(strings.NewReader(unattended(exampleConfig(), "synthetic")))
	pathCount, commandCount := 0, 0
	for {
		token, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		limit := 0
		switch start.Name.Local {
		case "Path":
			limit = 259
			pathCount++
		case "CommandLine":
			limit = 1024
			commandCount++
		default:
			continue
		}
		var value string
		if err := d.DecodeElement(&value, &start); err != nil {
			t.Fatal(err)
		}
		if n := len(utf16.Encode([]rune(value))); n == 0 || n > limit {
			t.Fatalf("%s exceeds Windows schema limit %d", start.Name.Local, limit)
		}
		if start.Name.Local == "Path" && !strings.HasSuffix(value, `-File C:\Windows\Panther\Unattend\specialize.ps1`) {
			t.Fatal("specialize must use the staged fixed script")
		}
	}
	if pathCount != 1 || commandCount != 1 {
		t.Fatal("expected setup commands missing")
	}
}

func TestDesktopLauncherUsesLengthFrameWithoutWaitingForEOF(t *testing.T) {
	command := desktopValidationCommand()
	if len(utf16.Encode([]rune(command))) > 4096 {
		t.Fatal("desktop launcher risks the Windows shell command limit")
	}
	value := `synthetic <&'" $() ; | > data`
	script := "param($data)\n#" + strings.Repeat("padding", 160000) + "\n[Console]::Out.Write($data.value);exit 0"
	input, err := guestScriptInput(script, map[string]string{"value": value})
	if err != nil || len(input) < 1<<20 {
		t.Fatal("fixture must exercise a large framed payload")
	}
	if int(binary.LittleEndian.Uint32(input[:4])) != len(input)-4 {
		t.Fatal("length prefix does not describe the exact UTF-8 payload")
	}
	if len(bytes.Split(input[4:], []byte{'\n'})) != 1 {
		t.Fatal("JSON fixture unexpectedly depends on line delimiters")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close(); _ = writer.Close() }()
	cmd := exec.CommandContext(ctx, filepath.Join(sys, "cmd.exe"), "/d", "/s", "/c", command)
	cmd.Stdin = reader
	cmd.WaitDelay = 2 * time.Second
	var out boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal("small launcher failed to start")
	}
	if _, err := writer.Write(input); err != nil {
		t.Fatal("framed input write failed")
	}
	// Deliberately keep stdin open: frame receipt, not EOF, starts execution.
	if err := cmd.Wait(); err != nil {
		t.Fatal("framed launcher waited for EOF or failed")
	}
	if string(out.data) != value {
		t.Fatal("stdin data was changed or interpreted as code")
	}
}

func TestDesktopLengthFrameRejectsOversizedAndTruncatedPayloads(t *testing.T) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		size uint32
		body string
	}{{0, ""}, {100000001, ""}, {32, "{}"}} {
		input := make([]byte, 4)
		binary.LittleEndian.PutUint32(input, item.size)
		input = append(input, item.body...)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, filepath.Join(sys, "cmd.exe"), "/d", "/s", "/c", desktopValidationCommand())
		cmd.Stdin = bytes.NewReader(input)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		err := cmd.Run()
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 18 {
			t.Fatal("invalid frame was not rejected before script execution")
		}
	}
}

func TestDesktopRequestCarriesOnlySmallMetadataAndFixedEntry(t *testing.T) {
	c := exampleConfig()
	c.RenderProbe = &PinnedFile{Source: `C:\SyntheticPrivateResource\render.exe`, SHA256: c.BaselineSHA256}
	c.SetupAssets = setupFixture(c)
	input, err := desktopScriptInput(c)
	if err != nil || len(input) > 1024 {
		t.Fatal("desktop metadata frame grew beyond the small transfer bound")
	}
	if bytes.Contains(input, []byte(c.RenderProbe.Source)) || bytes.Contains(input, []byte(`"probe":`)) {
		t.Fatal("host resource or binary appeared in SSH metadata")
	}
	var payload struct {
		Script string         `json:"script"`
		Data   map[string]any `json:"data"`
	}
	if json.Unmarshal(input[4:], &payload) != nil || payload.Script != guestValidateEntry {
		t.Fatal("fixed entry payload missing")
	}
	hash, ok := payload.Data["script_sha256"].(string)
	if !ok || len(hash) != 64 || len(payload.Data) != 5 || payload.Data["sha256"] != c.RenderProbe.SHA256 {
		t.Fatal("guest resource integrity pins missing")
	}
}
