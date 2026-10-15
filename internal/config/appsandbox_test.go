package config

import (
	"strings"
	"testing"
)

const windowsExample = `
[github]
url = "https://github.com/example-org"
app_client_id = "12345"
app_installation_id = 67890
private_key_secret = "app-key"
demand = "jit"
[budget]
max_instances = 1
[providers.windows]
type = "appsandbox"
labels = ["self-hosted", "Windows", "X64", "bivouac-windows-experimental"]
idle_pool = 1
[providers.windows.appsandbox]
experimental = true
broker_secret = "windows-broker"
baseline = "ci-template"
cpu = 4
memory_gb = 8
disk_gb = 80
gpu = true
runner_dir = 'C:\actions-runner'
`

func TestWindowsConfigRequiresExplicitIsolatedSettings(t *testing.T) {
	if _, err := Parse([]byte(windowsExample)); err != nil {
		t.Fatal(err)
	}
	for _, change := range [][2]string{
		{"experimental = true", "experimental = false"},
		{"cpu = 4", "cpu = 0"},
		{"memory_gb = 8", "memory_gb = 0"},
		{"disk_gb = 80", "disk_gb = 1"},
		{"baseline = \"ci-template\"", "baseline = \"name-too-long-for-windows\""},
		{`runner_dir = 'C:\actions-runner'`, `runner_dir = '\\server\share'`},
	} {
		if _, err := Parse([]byte(strings.Replace(windowsExample, change[0], change[1], 1))); err == nil {
			t.Errorf("accepted invalid %s", change[1])
		}
	}
	if _, err := Parse([]byte(windowsExample + "\n[cache]\nenabled = true\nguest_host = \"10.250.0.1\"\n")); err == nil {
		t.Fatal("host-cache isolation exception accepted")
	}
}

func TestWindowsCacheUsesRestrictedTransportDefaults(t *testing.T) {
	c, err := Parse([]byte(windowsExample + "\n[cache]\nenabled=true\nrelease_proxy=true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Cache.Listen != "127.0.0.1:0" || c.Cache.GuestHost != "127.0.0.1" {
		t.Fatal("cache exposed a host-network endpoint")
	}
	for _, listen := range []string{"0.0.0.0:0", "[::]:0", "10.0.0.1:0", "localhost:0"} {
		if _, err = Parse([]byte(windowsExample + "\n[cache]\nenabled=true\nlisten=\"" + listen + "\"\n")); err == nil {
			t.Fatalf("accepted unsafe listen %s", listen)
		}
	}
}
