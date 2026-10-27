package vz

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/linuxguest"
	"github.com/GomerPiles/bivouac/internal/vm"
	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

func TestLinuxBaselineAdmissionBuildMessagesAndHelperFreshness(t *testing.T) {
	p, r, spec := linuxProvider(t)
	for _, name := range []string{vzrecipe.DefaultName, "custom-missing"} {
		_, err := CheckLinuxBaseline(string(p.store), name, p.runner.Helper, p.name)
		if err == nil || !strings.Contains(err.Error(), "`"+BaselineBuildCommand(name, p.name, false)+"`") {
			t.Fatal("missing build guidance", err)
		}
		if name != vzrecipe.DefaultName && !strings.Contains(err.Error(), "`bivouac vz import`") {
			t.Fatal("custom image lacks import guidance", err)
		}
	}
	recipe := vzrecipe.Registry()[0]
	m, err := vm.ReadManifest(p.vmDir(spec.Baseline))
	if err != nil {
		t.Fatal(err)
	}
	m.Guest.Sudo = false
	m.Build = &vm.Build{Recipe: recipe.Name, SourceURL: recipe.Source.URLs[0], SourceSHA256: recipe.Source.SHA256, RunnerURL: recipe.Runner.URLs[0], RunnerSHA256: recipe.Runner.SHA256, HelperSHA256: strings.Repeat("a", 64), HostSHA256: strings.Repeat("b", 64), DiskBytes: 64 * vzrecipe.GiB}
	if err := vm.WriteManifest(p.vmDir(spec.Baseline), m); err != nil {
		t.Fatal(err)
	}
	_, err = CheckRunnerBaseline(string(p.store), spec.Baseline, p.name, p.runner)
	want := "built for another helper; run `" + BaselineBuildCommand(spec.Baseline, p.name, true) + "`"
	if err == nil || err.Error() != want {
		t.Fatal("freshness guidance differs", err)
	}
	if err := p.Create(context.Background(), spec); err == nil || err.Error() != want || len(r.calls) != 0 {
		t.Fatal("Create bypassed shared freshness admission", err)
	}
	hash, err := linuxguest.HelperSHA256(p.runner.Helper)
	if err != nil {
		t.Fatal(err)
	}
	m.Build.HelperSHA256 = hash
	if err := vm.WriteManifest(p.vmDir(spec.Baseline), m); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckRunnerBaseline(string(p.store), spec.Baseline, p.name, p.runner); err != nil {
		t.Fatal("matching baseline refused", err)
	}
}
func TestFactoryGateSharesReadinessAndRequiresRootGrowth(t *testing.T) {
	cfg := linuxguest.GuestConfig{Profile: linuxguest.VZ, Name: "bivouac-factory-fixture", ControllerID: "factory-fixture", RunnerDir: "/opt/actions-runner"}
	hash := strings.Repeat("a", 64)
	for _, kind := range []string{"success", "small-root", "root-overflow", "root-output", "cloud-init", "helper", "root-agent", "profile", "output-bound"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			exec := func(ctx context.Context, args []string, in io.Reader, limit int) ([]byte, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Error("caller deadline was lost")
				}
				calls++
				switch args[0] {
				case "/usr/bin/uname":
					if args[1] == "-s" {
						return []byte("Linux"), nil
					}
					return []byte("aarch64"), nil
				case "/usr/bin/id":
					if kind == "root-agent" {
						return []byte("0"), nil
					}
					return []byte("1000"), nil
				case "/bin/sh":
					probe := hash
					if kind == "helper" {
						probe = strings.Repeat("b", 64)
					}
					return []byte(probe + "  " + linuxguest.PreparedHelper), nil
				case linuxguest.PreparedHelper:
					if kind == "output-bound" {
						return make([]byte, 4097), nil
					}
					var c linuxguest.GuestConfig
					if err := json.NewDecoder(in).Decode(&c); err != nil {
						return nil, err
					}
					c.BootID = "12345678-1234-1234-1234-123456789abc"
					if kind == "profile" {
						c.Profile = linuxguest.Crosvm
					}
					return json.Marshal(linuxguest.GuestPreparation{Config: c, DNSDHCP: true})
				case "/usr/bin/test":
					if kind == "cloud-init" {
						return nil, errors.New("missing marker")
					}
					return nil, nil
				case "/usr/bin/stat":
					switch kind {
					case "small-root":
						return []byte("4096 1000"), nil
					case "root-overflow":
						return []byte("4096 18446744073709551615"), nil
					case "root-output":
						return []byte("not geometry"), nil
					}
					return []byte("4096 16000000"), nil
				}
				return nil, errors.New("unexpected gate operation")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			err := CheckLinuxFactoryGate(ctx, exec, cfg, hash, 64*vzrecipe.GiB)
			if (err == nil) != (kind == "success") || calls == 0 {
				t.Fatal("wrong gate result", err)
			}
		})
	}
}

func TestHistoricalFactoryPinsAreReadableButRefuseNewAdmission(t *testing.T) {
	for _, kind := range []string{"recipe", "source-url", "source-hash", "runner-url", "runner-hash", "agent"} {
		t.Run(kind, func(t *testing.T) {
			p, _, spec := linuxProvider(t)
			m, err := vm.ReadManifest(p.vmDir(spec.Baseline))
			if err != nil {
				t.Fatal(err)
			}
			hash, err := linuxguest.HelperSHA256(p.runner.Helper)
			if err != nil {
				t.Fatal(err)
			}
			r := vzrecipe.Registry()[0]
			m.Guest.Sudo = false
			m.Build = &vm.Build{Recipe: r.Name, SourceURL: r.Source.URLs[0], SourceSHA256: r.Source.SHA256, RunnerURL: r.Runner.URLs[0], RunnerSHA256: r.Runner.SHA256, HelperSHA256: hash, HostSHA256: strings.Repeat("b", 64), DiskBytes: 64 * vzrecipe.GiB}
			if err := vm.WriteManifest(p.vmDir(spec.Baseline), m); err != nil {
				t.Fatal(err)
			}
			bootLinuxFixture(t, p, spec)
			switch kind {
			case "recipe":
				m.Build.Recipe = "old-recipe"
			case "source-url":
				m.Build.SourceURL = "https://example.com/old-image"
			case "source-hash":
				m.Build.SourceSHA256 = strings.Repeat("c", 64)
			case "runner-url":
				m.Build.RunnerURL = "https://example.com/old-runner"
			case "runner-hash":
				m.Build.RunnerSHA256 = strings.Repeat("d", 64)
			case "agent":
				m.Guest.AgentVersion++
			}
			if err := vm.WriteManifest(p.vmDir(spec.Baseline), m); err != nil {
				t.Fatal("historical manifest unreadable", err)
			}
			if err := vm.WriteManifest(p.vmDir(spec.Name), m); err != nil {
				t.Fatal(err)
			}
			if err := p.ValidateRetained(spec.Name); err != nil {
				t.Fatal("historical clone cannot be retained", err)
			}
			if !p.HostLimitExempt(spec.Name) {
				t.Fatal("historical Linux clone lost host exemption")
			}
			if _, err := p.runnerLaunch(spec.Name); err != nil {
				t.Fatal("historical clone launch contract unreadable", err)
			}
			_, err = CheckLinuxBaseline(string(p.store), spec.Baseline, p.runner.Helper, p.name)
			want := "baseline build is stale; run `" + BaselineBuildCommand(spec.Baseline, p.name, true) + "`"
			if err == nil || err.Error() != want {
				t.Fatal("stale admission lacks exact replacement guidance", err)
			}
			if err := p.Stop(context.Background(), spec.Name, time.Second); err != nil {
				t.Fatal("historical clone cleanup refused", err)
			}
			if err := p.Delete(context.Background(), spec.Name); err != nil {
				t.Fatal("historical clone deletion refused", err)
			}
		})
	}
}
func TestBuildGuidanceNamesProviderAndCustomTarget(t *testing.T) {
	got := BaselineBuildCommand("custom", "linux", true)
	want := "bivouac vz build-baseline --provider linux --replace custom"
	if got != want {
		t.Fatalf("guidance = %q", got)
	}
	if got := BaselineBuildCommand(vzrecipe.DefaultName, "it's linux", false); got != `bivouac vz build-baseline --provider 'it'\''s linux'` {
		t.Fatalf("quoted guidance = %q", got)
	}
}
func TestSharedAgentWaitKeepsRunnerDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	want, _ := ctx.Deadline()
	exec := func(got context.Context, _ []string, _ io.Reader, _ int) ([]byte, error) {
		deadline, _ := got.Deadline()
		if !deadline.Equal(want) {
			t.Error("runner deadline was shortened")
		}
		return nil, nil
	}
	if err := WaitAgent(ctx, exec, nil, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
