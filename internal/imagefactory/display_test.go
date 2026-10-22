package imagefactory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFactorySetupAssets(t *testing.T) {
	c := testConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for index := range c.SetupAssets {
		bad := c
		bad.SetupAssets = append([]Asset(nil), c.SetupAssets[:index]...)
		bad.SetupAssets = append(bad.SetupAssets, c.SetupAssets[index+1:]...)
		if bad.Validate() == nil {
			t.Fatal("missing required helper accepted")
		}
	}
	for _, name := range []string{"AppSandboxVDD.dll", "AppSandboxVDD.inf", "AppSandboxVDD.cat", "AppSandboxVDD.sys", "devcon.exe", "DEVCON.EXE"} {
		bad := testConfig()
		bad.SetupAssets = append(bad.SetupAssets, Asset{Name: name, PinnedFile: PinnedFile{Source: `D:\Assets\` + name, SHA256: bad.SourceSHA256}})
		if bad.Validate() == nil {
			t.Fatal("unsupported display tool accepted")
		}
	}
	for _, name := range []string{"OpenSSH.msi", "RUNNER.ZIP"} {
		c.SetupAssets = append(c.SetupAssets, Asset{Name: name, PinnedFile: PinnedFile{Source: `D:\Assets\` + name, SHA256: c.SourceSHA256}})
	}
	if err := c.Validate(); err != nil {
		t.Fatal("optional assets refused", err)
	}
	b, _ := json.Marshal(c)
	if _, err := DecodeConfig(strings.NewReader(string(b))); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.Unmarshal(b, &fields) != nil {
		t.Fatal("config JSON")
	}
	if _, present := fields["display"]; present {
		t.Fatal("display field retained")
	}
	for _, value := range []string{"vdd", "synthetic", ""} {
		fields["display"] = value
		b, _ = json.Marshal(fields)
		if _, err := DecodeConfig(strings.NewReader(string(b))); err == nil {
			t.Fatal("removed display config accepted")
		}
	}
}
