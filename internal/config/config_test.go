package config

import (
	"strings"
	"testing"
)

func TestExampleParses(t *testing.T) {
	c, err := Parse([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	p := c.Providers["macos"]
	if p.Tart.Binary != "tart" || p.Tart.HostVMLimit != 2 {
		t.Fatalf("defaults not applied: %+v", p.Tart)
	}
	if c.Budget.JobTimeout.Hours() != 2 {
		t.Fatalf("job_timeout = %s", c.Budget.JobTimeout)
	}
}

func TestIsolatedContainersConfiguration(t *testing.T) {
	for _, engine := range []string{"docker", "podman"} {
		c, err := Parse([]byte(Example + "\n[providers.macos.tart.containers]\nengine = \"" + engine + "\"\nbaseline = \"ci-linux-engine\"\ncpu = 2\nmemory_gb = 2\nhelper = \"/opt/bivouac/linux-arm64\"\n"))
		if err != nil {
			t.Fatal(err)
		}
		p := c.Providers["macos"]
		for _, a := range []string{"--dir=/tmp:ro", "--disk=/dev/disk1", "--net-host", "--net-softnet-allow=0.0.0.0/0", "--net-softnet-block=127.0.0.0/8", "--net-bridged=en0", "--net-softnet-expose=2375:2375", "--rosetta=host", "--nested"} {
			p.Tart.ExtraArgs = []string{a}
			if c.Validate() == nil {
				t.Fatalf("accepted isolation override %q", a)
			}
		}
		p.Tart.ExtraArgs = nil
		p.Tart.BootstrapShare = "/tmp"
		if c.Validate() == nil {
			t.Fatal("accepted host share")
		}
		p.Tart.BootstrapShare = ""
		c.Cache = Cache{Enabled: true, GuestHost: "192.168.64.1", Listen: "0.0.0.0:0", MaxGB: 4, MaxObjectMB: 1}
		if c.Validate() == nil {
			t.Fatal("accepted gateway cache exception")
		}
		c.Cache = Cache{}
		p.Tart.Containers.Engine = "host"
		if c.Validate() == nil {
			t.Fatal("accepted host engine")
		}
		p.Tart.Containers.Engine = engine
		p.Tart.Containers.Baseline = "bivouac-linux"
		if c.Validate() == nil {
			t.Fatal("accepted owned prefix baseline")
		}
		p.Tart.Containers.Baseline = "ci-linux-engine"
		p.Tart.CPU = 0
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
		"shell string arg": strings.Replace(Example, `"--no-audio"`, `"--no-audio --no-clipboard"`, 1),
		"foreign slots":    strings.Replace(Example, `foreign_slots = 1`, `foreign_slots = 2`, 1),
		"missing key":      strings.Replace(Example, `private_key_secret = "github-app-key"`, ``, 1),
		"bad url":          strings.Replace(Example, `https://github.com/example-org`, `http://github.com/example-org`, 1),
		"negative timeout": strings.Replace(Example, `job_timeout = "2h"`, `job_timeout = "-2h"`, 1),
		"negative idle":    strings.Replace(Example, `idle_timeout = "10m"`, `idle_timeout = "-1s"`, 1),
		"tart cpu":         strings.Replace(Example, `cpu = 6`, `cpu = -1`, 1),
		"tart memory":      strings.Replace(Example, `memory_gb = 8`+"\n"+`extra_args`, `memory_gb = 4096`+"\n"+`extra_args`, 1),
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
	if cfg.Cache.ReleaseProxy {
		t.Fatal("release interception must be opt-in")
	}
	if _, err = Parse([]byte(good + "release_proxy = true\n")); err != nil {
		t.Fatal("enabled release proxy rejected", err)
	}
	for _, bad := range []Cache{{ReleaseProxy: true}, {Enabled: true, GuestHost: "not-an-ip", Listen: "0.0.0.0:0", MaxGB: 4, MaxObjectMB: 512}, {Enabled: true, GuestHost: "192.168.64.1", Listen: "bad", MaxGB: 4, MaxObjectMB: 512}, {Enabled: true, GuestHost: "192.168.64.1", Listen: "0.0.0.0:0", MaxGB: 4, MaxObjectMB: 8192}} {
		cfg.Cache = bad
		if cfg.Validate() == nil {
			t.Fatal("invalid cache config accepted")
		}
	}
}

func TestTartSerialArgumentRejected(t *testing.T) {
	for _, a := range []string{"--serial", "--serial=/tmp/console"} {
		cfg, err := Parse([]byte(Example))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Providers["macos"].Tart.ExtraArgs = []string{"--no-audio", a}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "--serial") {
			t.Fatalf("%s accepted: %v", a, err)
		}
	}
}
