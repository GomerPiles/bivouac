package config

import (
	"strings"
	"testing"
)

const hcsExample = `
[github]
url = "https://github.com/example-org"
app_client_id = "12345"
app_installation_id = 67890
private_key_secret = "app-key"
demand = "jit"
[budget]
max_instances = 1
[providers.windows]
type = "hcs"
labels = ["self-hosted", "Windows", "X64", "bivouac-windows-hcs"]
idle_pool = 1
[providers.windows.hcs]
experimental = true
image = "windows"
guest_name = "bivouac-image"
guest_user = "ciuser"
cpu = 4
memory_gb = 8
gpu = true
runner_dir = 'C:\actions-runner'
`

func TestHCSConfigRequiresBoundedExplicitSettings(t *testing.T) {
	c, err := Parse([]byte(hcsExample))
	if err != nil {
		t.Fatal(err)
	}
	if h := c.Providers["windows"].HCS; h == nil || h.Image != "windows" || h.CPU != 4 || h.MemoryGB != 8 {
		t.Fatal("hcs settings not parsed", h)
	}
	if c.Cache.Listen != "127.0.0.1:0" || c.Cache.GuestHost != "127.0.0.1" {
		t.Fatal("HCS host defaults must use loopback", c.Cache.Listen, c.Cache.GuestHost)
	}
	for _, change := range [][2]string{
		{"experimental = true", "experimental = false"},
		{`image = "windows"`, `image = 'C:\Images\x.vhdx'`},
		{`guest_name = "bivouac-image"`, `guest_name = "name-too-long-for-windows"`},
		{`guest_user = "ciuser"`, `guest_user = "Domain\user"`},
		{"cpu = 4", "cpu = 0"},
		{"memory_gb = 8", "memory_gb = 0"},
		{`runner_dir = 'C:\actions-runner'`, `runner_dir = '\\server\share'`},
		{`runner_dir = 'C:\actions-runner'`, "runner_dir = 'C:\\actions-runner'\nrunner_archive = 'C:\\runner.zip'"},
	} {
		if _, err := Parse([]byte(strings.Replace(hcsExample, change[0], change[1], 1))); err == nil {
			t.Errorf("accepted invalid %s", change[1])
		}
	}
	if _, err := Parse([]byte(hcsExample + "\n[cache]\nenabled = true\n")); err == nil {
		t.Fatal("unsupported cache accepted for hcs guests")
	}
	both := strings.Replace(hcsExample, "[providers.windows.hcs]", "[providers.windows.appsandbox]\nexperimental = true\n[providers.windows.hcs]", 1)
	if _, err := Parse([]byte(both)); err == nil {
		t.Fatal("mixed provider settings accepted")
	}
}
