package vm

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/rootnet"
	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

func TestManifestBuildProvenance(t *testing.T) {
	r := vzrecipe.Registry()[0]
	m, err := NewLinuxManifest(4, 4)
	if err != nil {
		t.Fatal(err)
	}
	m.Build = &Build{Recipe: r.Name, SourceURL: r.Source.URLs[0], SourceSHA256: r.Source.SHA256, RunnerURL: r.Runner.URLs[0], RunnerSHA256: r.Runner.SHA256, HelperSHA256: strings.Repeat("a", 64), HostSHA256: strings.Repeat("b", 64), DiskBytes: 64 * vzrecipe.GiB}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseManifest(b); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"recipe-shape", "source", "source-hash", "runner", "runner-hash", "helper", "host", "disk"} {
		t.Run(kind, func(t *testing.T) {
			copyM := m
			build := *m.Build
			copyM.Build = &build
			switch kind {
			case "recipe-shape":
				build.Recipe = "bad recipe"
			case "source":
				build.SourceURL = "http://example.com/image"
			case "source-hash":
				build.SourceSHA256 = "bad"
			case "runner":
				build.RunnerURL += "?credential=forbidden"
			case "runner-hash":
				build.RunnerSHA256 = "bad"
			case "helper":
				build.HelperSHA256 = strings.Repeat("A", 64)
			case "host":
				build.HostSHA256 = ""
			case "disk":
				build.DiskBytes = 512*vzrecipe.GiB + 1
			}
			if copyM.validate() == nil {
				t.Fatal("invalid provenance accepted")
			}
		})
	}
	m.Build.Recipe = "historical-recipe"
	m.Build.SourceURL = "https://example.com/old-image"
	m.Build.SourceSHA256 = strings.Repeat("c", 64)
	m.Build.RunnerSHA256 = strings.Repeat("d", 64)
	m.Guest.AgentVersion++
	if err := m.validate(); err != nil {
		t.Fatal("historical build became unreadable", err)
	}
	m.Build = nil
	if err := m.validate(); err != nil {
		t.Fatal("import contract changed", err)
	}
}
func TestFactoryDisksRoundTripAndRefusedByRunnerProof(t *testing.T) {
	dir := t.TempDir()
	o := RunOptions{Dir: dir, AgentSocket: filepath.Join("/tmp", "factory.sock"), AgentPort: 1, RootlessNetwork: true, Machine: MachineOptions{SeedDisk: filepath.Join(dir, "seed.iso"), ReceiptDisk: filepath.Join(dir, "receipt.img"), DiskSync: "full"}}
	got, err := ParseArgs(o.Args())
	if err != nil || got.Machine != o.Machine {
		t.Fatal("factory flags changed", err)
	}
	for _, kind := range []string{"seed", "receipt", "both"} {
		c := o
		if kind == "seed" {
			c.Machine.ReceiptDisk = ""
		}
		if kind == "receipt" {
			c.Machine.SeedDisk = ""
		}
		if proveIsolationArgs(append([]string{"bivouac", "vm", "run"}, c.Args()...), dir, rootnet.PolicyID) == nil {
			t.Fatal("factory disks accepted by runner proof")
		}
	}
	if o.Machine.CheckGuest(Manifest{OS: "darwin"}) == nil {
		t.Fatal("Darwin accepted factory disks")
	}
	o.Machine.DiskSync = "none"
	if o.Machine.Validate() == nil {
		t.Fatal("weak factory synchronization")
	}
}
func TestHelperStopClassification(t *testing.T) {
	terminal, err := stoppedResult(false)
	if err != nil || terminal != "guest stopped" {
		t.Fatal("guest stop failed")
	}
	terminal, err = stoppedResult(true)
	if !errors.Is(err, ErrForcedStop) || terminal != "host forced power-off" {
		t.Fatal("forced stop accepted")
	}
}
