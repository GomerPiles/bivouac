package config

import (
	"strings"
	"testing"
)

func linuxVZConfig(t *testing.T) *Config {
	t.Helper()
	text := strings.Replace(Example, "[providers.macos.vz]\n", "[providers.macos.vz]\nguest_os = \"linux\"\nhelper = \"/opt/bivouac/linux-arm64\"\n", 1)
	text = strings.Replace(text, "host_vm_limit = 2", "", 1)
	text = strings.Replace(text, "foreign_slots = 1", "", 1)
	c, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVZLinuxConfigAndDarwinDefault(t *testing.T) {
	c := linuxVZConfig(t)
	v := c.Providers["macos"].VZ
	if v.RunnerOS() != "linux" || v.HostVMLimit != 0 {
		t.Fatal("Linux gained Apple slot defaults")
	}
	if (VZ{}).RunnerOS() != "darwin" {
		t.Fatal("Darwin default changed")
	}
	// One host cache config can coexist with Linux and Darwin providers. Linux
	// delivery remains disabled at the adapter, without weakening DNS agreement.
	c.Cache.Enabled = true
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestVZLinuxRejectsUnusedMacOSOptionsAndInvalidHelper(t *testing.T) {
	for _, kind := range []string{"OS", "helper", "helper-control", "cpu", "memory", "slots", "foreign", "display", "share", "containers", "baseline"} {
		t.Run(kind, func(t *testing.T) {
			c := linuxVZConfig(t)
			v := c.Providers["macos"].VZ
			switch kind {
			case "OS":
				v.GuestOS = "other"
			case "helper":
				v.Helper = "relative"
			case "helper-control":
				v.Helper = "/opt/helper\n"
			case "cpu":
				v.CPU = 0
			case "memory":
				v.MemoryGB = 0
			case "slots":
				v.HostVMLimit = 2
			case "foreign":
				v.ForeignSlots = 1
			case "display":
				v.Machine.Display = Display{Width: 1024, Height: 768}
			case "share":
				v.BootstrapShare = "/tmp"
			case "containers":
				v.Containers = &Containers{}
			case "baseline":
				v.Baseline = ""
			}
			if c.Validate() == nil {
				t.Fatal("invalid Linux settings accepted")
			}
		})
	}
	c, err := Parse([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	c.Providers["macos"].VZ.Helper = "/opt/helper"
	if c.Validate() == nil {
		t.Fatal("Darwin accepted unused Linux helper")
	}
}

func TestVZDNSAgreementIncludesLinuxButSlotsDoNot(t *testing.T) {
	c := linuxVZConfig(t)
	linux := c.Providers["macos"]
	linux.ScaleSet = "bivouac-linux-fixture"
	delete(c.Providers, "macos")
	c.Providers["alinux"] = linux
	other, err := Parse([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	c.Providers["macos"] = other.Providers["macos"]
	if err := c.Validate(); err != nil {
		t.Fatal("Linux slots entered Darwin agreement", err)
	}
	linux.VZ.Network.DNSServers = []string{"1.1.1.1"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "same network.dns_servers") {
		t.Fatal("Linux escaped DNS agreement", err)
	}
	c.Providers["macos"].VZ.Network.DNSServers = []string{"1.1.1.1"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	// Compare two Darwin providers even when the first provider is Linux.
	darwin := c.Providers["macos"]
	copyVZ := *darwin.VZ
	darwin.VZ = &copyVZ
	darwin.ScaleSet = "bivouac-studio-fixture"
	darwin.VZ.ForeignSlots = 0
	c.Providers["studio"] = darwin
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "host_vm_limit and foreign_slots") {
		t.Fatal("Darwin providers escaped slot agreement", err)
	}
}
