package config

import (
	"slices"
	"strings"
	"testing"
)

func TestMachineOptionsParse(t *testing.T) {
	text := strings.Replace(Example, "# [providers.macos.vz.machine]\n# display = { width = 1920, height = 1080, ppi = 144 }\n# disk_sync = \"none\"", "[providers.macos.vz.machine]\ndisplay = { width = 1920, height = 1080, ppi = 144 }\ndisk_sync = \"none\"", 1)
	c, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if m := c.Providers["macos"].VZ.Machine; m != (Machine{Display: Display{Width: 1920, Height: 1080, PPI: 144}, DiskSync: "none"}) {
		t.Fatalf("machine = %+v", m)
	}
}

func TestExampleParses(t *testing.T) {
	c, err := Parse([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	p := c.Providers["macos"]
	if p.VZ.HostVMLimit != 2 {
		t.Fatalf("defaults not applied: %+v", p.VZ)
	}
	if c.Budget.JobTimeout.Hours() != 2 {
		t.Fatalf("job_timeout = %s", c.Budget.JobTimeout)
	}
}

func TestIsolatedContainersConfiguration(t *testing.T) {
	for _, engine := range []string{"docker", "podman"} {
		c, err := Parse([]byte(Example + "\n[providers.macos.vz.containers]\nengine = \"" + engine + "\"\nbaseline = \"ci-linux-engine\"\ncpu = 2\nmemory_gb = 2\nhelper = \"/opt/bivouac/linux-arm64\"\n"))
		if err != nil {
			t.Fatal(err)
		}
		p := c.Providers["macos"]
		p.VZ.BootstrapShare = "/tmp"
		if c.Validate() == nil {
			t.Fatal("accepted host share")
		}
		p.VZ.BootstrapShare = ""
		c.Cache = Cache{Enabled: true, GuestHost: "192.168.64.1", Listen: "0.0.0.0:0", MaxGB: 4, MaxObjectMB: 1}
		if c.Validate() == nil {
			t.Fatal("accepted gateway cache exception")
		}
		c.Cache = Cache{}
		p.VZ.Containers.Engine = "host"
		if c.Validate() == nil {
			t.Fatal("accepted host engine")
		}
		p.VZ.Containers.Engine = engine
		p.VZ.Containers.Baseline = "bivouac-linux"
		if c.Validate() == nil {
			t.Fatal("accepted owned prefix baseline")
		}
		p.VZ.Containers.Baseline = "ci-linux-engine"
		p.VZ.CPU = 0
		if c.Validate() == nil {
			t.Fatal("accepted unknown pair resource size")
		}
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":      strings.Replace(Example, "reserve_cpu", "reserve_cpus", 1),
		"baseline prefix":  strings.Replace(Example, `baseline = "ci-macos"`, `baseline = "bivouac-base"`, 1),
		"scaleset prefix":  strings.Replace(Example, `scaleset = "bivouac-macos-experimental"`, `scaleset = "macos"`, 1),
		"foreign slots":    strings.Replace(Example, `foreign_slots = 1`, `foreign_slots = 2`, 1),
		"missing key":      strings.Replace(Example, `private_key_secret = "github-app-key"`, ``, 1),
		"bad url":          strings.Replace(Example, `https://github.com/example-org`, `http://github.com/example-org`, 1),
		"negative timeout": strings.Replace(Example, `job_timeout = "2h"`, `job_timeout = "-2h"`, 1),
		"negative idle":    strings.Replace(Example, `idle_timeout = "10m"`, `idle_timeout = "-1s"`, 1),
		"vz cpu":           strings.Replace(Example, `cpu = 6`, `cpu = -1`, 1),
		"vz memory":        strings.Replace(Example, `memory_gb = 8`+"\n"+`host_vm_limit`, `memory_gb = 4096`+"\n"+`host_vm_limit`, 1),
		"vz runner_dir":    strings.Replace(Example, `memory_gb = 8`+"\n", `memory_gb = 8`+"\n"+`runner_dir = "/Users/admin/actions-runner"`+"\n", 1),
		"machine display":  strings.Replace(Example, "# [providers.macos.vz.machine]\n# display = { width = 1920, height = 1080, ppi = 144 }", "[providers.macos.vz.machine]\ndisplay = { width = 1920 }", 1),
		"machine sync":     strings.Replace(Example, "# [providers.macos.vz.machine]\n# display = { width = 1920, height = 1080, ppi = 144 }\n# disk_sync = \"none\"", "[providers.macos.vz.machine]\ndisk_sync = \"unsafe\"", 1),
	}
	for name, text := range cases {
		if _, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestJITPoolConfiguration(t *testing.T) {
	cfg, err := Parse([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	cfg.GitHub.Demand = DemandJIT
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, labels := range [][]string{{"tartelet"}, {"bivouac-experimental", ""}, {"bivouac-experimental", "BIVOUAC-EXPERIMENTAL"}} {
		p := cfg.Providers["macos"]
		p.Labels = labels
		cfg.Providers["macos"] = p
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted unsafe/invalid JIT labels: %v", labels)
		}
	}
	p := cfg.Providers["macos"]
	p.Labels = []string{"bivouac-experimental"}
	p.IdlePool = 0
	cfg.Providers["macos"] = p
	if err := cfg.Validate(); err == nil {
		t.Fatal("accepted pool that cannot receive jobs")
	}
	p.IdlePool = 2
	cfg.Providers["macos"] = p
	if err := cfg.Validate(); err == nil {
		t.Fatal("accepted pool exceeding budget")
	}
}

func TestCacheConfiguration(t *testing.T) {
	good := Example + "\n[cache]\nenabled = true\nguest_host = \"192.168.64.1\"\nmax_gb = 4\nmax_object_mb = 512\n"
	cfg, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Cache.Enabled || cfg.Cache.Listen != "0.0.0.0:0" {
		t.Fatalf("cache listen default %q, want every interface", cfg.Cache.Listen)
	}
	if explicit, err := Parse([]byte(good + "listen = \"0.0.0.0:8443\"\n")); err != nil || explicit.Cache.Listen != "0.0.0.0:8443" {
		t.Fatalf("explicit listen not kept: %v", err)
	}
	if cfg.Cache.StoreUploads {
		t.Fatal("upload storage must be opt-in")
	}
	if _, err = Parse([]byte(good + "store_uploads = true\n")); err != nil {
		t.Fatal("enabled upload storage rejected", err)
	}
	if cfg.Cache.ReleaseProxy {
		t.Fatal("release interception must be opt-in")
	}
	if _, err = Parse([]byte(good + "release_proxy = true\n")); err != nil {
		t.Fatal("enabled release proxy rejected", err)
	}
	for _, bad := range []Cache{{ReleaseProxy: true}, {StoreUploads: true}, {Enabled: true, GuestHost: "not-an-ip", Listen: "0.0.0.0:0", MaxGB: 4, MaxObjectMB: 512}, {Enabled: true, GuestHost: "192.168.64.1", Listen: "bad", MaxGB: 4, MaxObjectMB: 512}, {Enabled: true, GuestHost: "192.168.64.1", Listen: "0.0.0.0:0", MaxGB: 4, MaxObjectMB: 8192}} {
		cfg.Cache = bad
		if cfg.Validate() == nil {
			t.Fatal("invalid cache config accepted")
		}
	}
}

func TestNestedVirtualizationParses(t *testing.T) {
	text := Example + "\n[providers.macos.vz.machine]\nnested_virtualization = true\n"
	c, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Providers["macos"].VZ.Machine.NestedVirtualization {
		t.Fatal("nested_virtualization not parsed")
	}
}

func TestScaleSetLabels(t *testing.T) {
	cfg, err := Parse([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Providers["macos"]
	p.ScaleSetLabels = []string{"self-hosted", "bivouac-lt-a"}
	cfg.Providers["macos"] = p
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := p.ScaleSetLabelNames(); !slices.Equal(got, []string{"bivouac-macos-experimental", "self-hosted", "bivouac-lt-a"}) {
		t.Fatalf("labels %q", got)
	}
	for _, labels := range [][]string{{""}, {" padded"}, {"BIVOUAC-MACOS-EXPERIMENTAL"}, {"a", "A"}, slices.Repeat([]string{"x"}, 100)} {
		p.ScaleSetLabels = labels
		cfg.Providers["macos"] = p
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted invalid scale set labels: %q", labels)
		}
	}
}
