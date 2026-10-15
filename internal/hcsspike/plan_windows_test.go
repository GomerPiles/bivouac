//go:build windows

package hcsspike

import (
	"encoding/json"
	"strings"
	"testing"
)

func exampleConfig() Config {
	return Config{Root: `C:\Tests\HCS-Spike`, InstanceID: "00112233445566778899aabbccddeeff", Baseline: `C:\Tests\Images\specialized.vhdx`, BaselineSHA256: strings.Repeat("a", 64), GuestUser: "ciuser", CPU: 2, MemoryMB: 2048, GPU: true, TimeoutSeconds: 180}
}

func TestPlanHasNoNetworkOrPersonalShares(t *testing.T) {
	c := exampleConfig()
	c.Drivers = []DriverShare{{Source: `C:\Tests\Drivers\vendor`, GuestPath: `C:\Windows\HostDriverStore\FileRepository\vendor`}}
	p, err := Plan(c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"NetworkAdapters", "VirtualSmb", "ComPorts", "ExposeVirtualizationExtensions", "AllowOvercommit", "EnableDeferredCommit", `C:\\Tests\\Drivers`, "Clipboard", "Audio"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("plan includes forbidden field/path %s", forbidden)
		}
	}
	if !strings.HasPrefix(c.name(), "bivouac-") || len(c.name()) != 15 {
		t.Fatalf("unexpected native name %q", c.name())
	}
	if p["Owner"] != c.owner() || p["ShouldTerminateOnLastHandleClosed"] != true {
		t.Fatal("missing owner or bounded handle lifetime")
	}
	devices := p["VirtualMachine"].(map[string]any)["Devices"].(map[string]any)
	shares := devices["Plan9"].(map[string]any)["Shares"].([]map[string]any)
	if len(shares) != 1 || shares[0]["Flags"] != 1 || !strings.HasPrefix(shares[0]["Path"].(string), c.directory()) {
		t.Fatal("driver share is not a read-only owned copy")
	}
	services := devices["HvSocket"].(map[string]any)["HvSocketConfig"].(map[string]any)["ServiceTable"].(map[string]any)
	if len(services) != 2 {
		t.Fatal("unexpected guest services exposed")
	}
	for _, port := range []uint16{1, 7} {
		if _, ok := services[serviceID(port).String()]; !ok {
			t.Fatal("agent/SSH service mapping differs")
		}
	}
}

func TestConfigRejectsUnsafeInputs(t *testing.T) {
	tests := map[string]func(*Config){
		"root volume":          func(c *Config) { c.Root = `C:\` },
		"production root":      func(c *Config) { c.Root = `C:\Tests\Instances` },
		"UNC":                  func(c *Config) { c.Root = `\\server\share\HCS-Spike` },
		"device path":          func(c *Config) { c.Root = `\\?\C:\HCS-Spike` },
		"relative":             func(c *Config) { c.Root = `HCS-Spike` },
		"alias":                func(c *Config) { c.Root = `C:\Tests.\HCS-Spike` },
		"device name":          func(c *Config) { c.Root = `C:\NUL\HCS-Spike` },
		"traversal":            func(c *Config) { c.Root = `C:\Tests\..\HCS-Spike` },
		"baseline inside root": func(c *Config) { c.Baseline = c.Root + `\disk.vhdx` },
		"baseline hash":        func(c *Config) { c.BaselineSHA256 = "bad" },
		"ID traversal":         func(c *Config) { c.InstanceID = `..\foreign` },
		"ID uppercase":         func(c *Config) { c.InstanceID = strings.ToUpper(c.InstanceID) },
		"CPU budget":           func(c *Config) { c.CPU = 128 },
		"odd memory":           func(c *Config) { c.MemoryMB = 2049 },
		"unbounded duration":   func(c *Config) { c.TimeoutSeconds = 0 },
		"user injection":       func(c *Config) { c.GuestUser = "ci\ncommand" },
		"destination injection": func(c *Config) {
			c.Drivers = []DriverShare{{Source: `C:\Drivers`, GuestPath: "C:\\Windows\\HostDriverStore\\FileRepository\\x|other"}}
		},
		"arbitrary guest destination": func(c *Config) { c.Drivers = []DriverShare{{Source: `C:\Drivers`, GuestPath: `C:\Users\ciuser`}} },
		"source contains root": func(c *Config) {
			c.Drivers = []DriverShare{{Source: `C:\Tests`, GuestPath: `C:\Windows\HostDriverStore\FileRepository\x`}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c := exampleConfig()
			mutate(&c)
			if _, err := Plan(c); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestDecodeConfigIsBoundedAndStrict(t *testing.T) {
	b, err := json.Marshal(exampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{string(b) + " {}", strings.Repeat(" ", 65537), strings.Replace(string(b), `"cpu":2`, `"cpu":2,"password":"synthetic"`, 1), "null"} {
		if _, err := DecodeConfig(strings.NewReader(input)); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, err := DecodeConfig(strings.NewReader(string(b))); err != nil {
		t.Fatal(err)
	}
}
