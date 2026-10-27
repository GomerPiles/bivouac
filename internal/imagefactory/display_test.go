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
	for _, name := range []string{"AppSandboxVDD.dll", "AppSandboxVDD.inf", "AppSandboxVDD.cat", "AppSandboxVDD.sys", "devcon.exe", "DEVCON.EXE", "appsandbox-agent.exe", "appsandbox-input.exe", "appsandbox-displays.exe", "OpenSSH.msi"} {
		bad := testConfig()
		bad.SetupAssets = append(bad.SetupAssets, Asset{Name: name, PinnedFile: PinnedFile{Source: `D:\Assets\` + name, SHA256: bad.ISOSHA256}})
		if bad.Validate() == nil {
			t.Fatal("unsupported display tool accepted")
		}
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
