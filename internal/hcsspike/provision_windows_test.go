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
	entries, err := os.ReadDir(assets)
	if err != nil || len(entries) != 1 {
		t.Fatal("answer file was written into host staging")
	}
}
func TestRenderReportRejectsPartialAndSoftwareResults(t *testing.T) {
	good := renderResult{GuestReady: true, DesktopReady: true, HardwareD3D11: true, Presented: true, PixelReadback: true, Stage: 7, VendorID: 0x1002, DeviceID: 1}
	data, _ := json.Marshal(good)
	if _, err := validateRenderReport(data); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*renderResult){func(r *renderResult) { r.GuestReady = false }, func(r *renderResult) { r.DesktopReady = false }, func(r *renderResult) { r.PixelReadback = false }, func(r *renderResult) { r.Presented = false }, func(r *renderResult) { r.HardwareD3D11 = false }, func(r *renderResult) { r.HRESULT = 1 }, func(r *renderResult) { r.Stage = 6 }, func(r *renderResult) { r.VendorID = 0x1414; r.DeviceID = 0x8c }} {
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
