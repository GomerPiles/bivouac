package vz

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/linuxguest"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

type linuxRecorder struct {
	*recorder
	os, arch, uid, hash string
	report              []byte
	status              []byte
	diagnostics         []byte
	statusError         error
}

func (r *linuxRecorder) Run(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if len(args) < 3 || args[0] != "Exec" {
		return r.recorder.Run(ctx, args, in, out)
	}
	var input []byte
	if in != nil {
		var err error
		input, err = io.ReadAll(in)
		if err != nil {
			return err
		}
		in = bytes.NewReader(input)
	}
	if err := r.recorder.Run(ctx, args, in, io.Discard); err != nil {
		return err
	}
	if len(args) < 3 || args[0] != "Exec" {
		return nil
	}
	var value string
	switch args[2] {
	case "/usr/bin/uname":
		if args[3] == "-s" {
			value = r.os
		} else {
			value = r.arch
		}
	case "/usr/bin/id":
		value = r.uid
	case "/bin/sh":
		value = r.hash + "  " + linuxguest.PreparedHelper + "\n"
	case linuxguest.PreparedHelper:
		if r.report != nil {
			_, err := out.Write(r.report)
			return err
		}
		var cfg linuxguest.GuestConfig
		if json.Unmarshal(input, &cfg) != nil {
			return errors.New("invalid fixture preparation input")
		}
		cfg.BootID = "12345678-1234-1234-1234-123456789abc"
		return json.NewEncoder(out).Encode(linuxguest.GuestPreparation{Config: cfg, DNSDHCP: true})
	case linuxguest.RuntimeHelper:
		switch args[len(args)-1] {
		case "status":
			if r.statusError != nil {
				return r.statusError
			}
			if r.status != nil {
				_, err := out.Write(r.status)
				return err
			}
			return json.NewEncoder(out).Encode(provider.RunnerStatus{State: provider.RunnerListening})
		case "diagnostics":
			_, err := out.Write(r.diagnostics)
			return err
		}
	}
	_, err := io.WriteString(out, value)
	return err
}

func linuxProvider(t *testing.T) (*Provider, *linuxRecorder, provider.Spec) {
	t.Helper()
	r := newRecorder()
	r.vms["linux-base"] = false
	p := newProvider(t, r)
	helper := linuxHelperFixture(t)
	p.name = "linux"
	p.cfg.GuestOS, p.cfg.Baseline, p.cfg.Helper = "linux", "linux-base", helper
	p.cfg.HostVMLimit, p.cfg.ForeignSlots = 0, 0
	p.runner = GuestRuntime{OS: "linux", Helper: helper}
	linuxRunnerManifest(t, p.vmDir("linux-base"))
	hash, err := linuxguest.HelperSHA256(helper)
	if err != nil {
		t.Fatal(err)
	}
	lr := &linuxRecorder{recorder: r, os: "Linux", arch: "aarch64", uid: "1000", hash: hash}
	p.rt = callRuntime{lr}
	p.records, err = state.Open(t.TempDir(), func() string { return p.controllerID })
	if err != nil {
		t.Fatal(err)
	}
	name := "bivouac-linux-fixture"
	if err := p.records.Put(&state.Instance{ID: "fixture", Name: name, Provider: p.name, Phase: state.PhaseCreating, ScaleSetID: 100, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return p, lr, provider.Spec{Name: name, Baseline: "linux-base", CPU: 2, MemoryMB: 4096, Meta: provider.Metadata{ControllerID: p.controllerID, InstanceID: "fixture"}}
}

func bootLinuxFixture(t *testing.T, p *Provider, spec provider.Spec) {
	t.Helper()
	if err := p.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background(), spec.Name, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxRunnerLifecycleWithRootlessProof(t *testing.T) {
	p, r, spec := linuxProvider(t)
	ctx := context.Background()
	if caps := p.Capabilities(); caps.HostLimit != 0 || caps.DesktopSession || caps.GPU != provider.GPUNone {
		t.Fatal("Linux advertises macOS capabilities")
	}
	bootLinuxFixture(t, p, spec)
	if err := p.WaitReady(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	const jit = "synthetic-private-jit"
	if err := p.StartRunner(ctx, spec.Name, []byte(jit)); err != nil {
		t.Fatal(err)
	}
	for _, call := range r.calls {
		text := strings.Join(call, " ")
		if strings.Contains(text, jit) || strings.Contains(text, " session") || strings.Contains(text, "Start input") || strings.Contains(text, "share=") || strings.Contains(text, "dd of=") {
			t.Fatal("Linux used private argv, desktop setup or an upload fallback")
		}
	}
	if input := r.stdin["Exec "+spec.Name+" "+linuxguest.RuntimeHelper+" guest linux seed-jit"]; input != jit {
		t.Fatal("JIT not delivered on stdin")
	}
	if !strings.Contains(strings.Join(r.calls[1], " "), "rootless-network") {
		t.Fatal("Linux did not launch rootless")
	}
	var config linuxguest.GuestConfig
	if err := json.Unmarshal([]byte(r.stdin["Exec "+spec.Name+" "+linuxguest.PreparedHelper+" guest linux prepare"]), &config); err != nil || config.Profile != linuxguest.VZ {
		t.Fatal("VZ runtime profile lost", err)
	}
	// Adoption/status/cancellation must not read mutable baseline/helper inputs.
	if err := os.Remove(p.runner.Helper); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(p.vmDir(spec.Baseline)); err != nil {
		t.Fatal(err)
	}
	delete(r.vms, spec.Baseline)
	replacement, err := New(p.name, p.cfg, p.runner, p.controllerID, string(p.store), p.rt, nil)
	if err != nil {
		t.Fatal(err)
	}
	replacement.SetRecords(p.records)
	replacement.checkIsolation = func(context.Context) error { return nil }
	assertReconcilesRetainedRunner(t, replacement, spec.Name)
	if err := replacement.CheckRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	before := len(r.calls)
	if status, err := replacement.RunnerStatus(ctx, spec.Name); err != nil || status.State != provider.RunnerListening {
		t.Fatal("retained Linux runner not adoptable", err)
	}
	if err := replacement.StopRunner(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	for _, call := range r.calls[before:] {
		if strings.Contains(strings.Join(call, " "), "prepare") || strings.Contains(strings.Join(call, " "), "seed-jit") {
			t.Fatal("adoption repeated preparation/JIT")
		}
	}
	if err := replacement.Stop(ctx, spec.Name, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := replacement.Delete(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxReadinessRefusesIdentityAndUnpinnedHelper(t *testing.T) {
	for _, kind := range []string{"OS", "architecture", "root", "UID", "hash", "profile", "public-DNS", "report-bound"} {
		t.Run(kind, func(t *testing.T) {
			p, r, spec := linuxProvider(t)
			bootLinuxFixture(t, p, spec)
			switch kind {
			case "OS":
				r.os = "Darwin"
			case "architecture":
				r.arch = "x86_64"
			case "root":
				r.uid = "0"
			case "UID":
				r.uid = "invalid"
			case "hash":
				r.hash = strings.Repeat("0", 64)
			case "profile", "public-DNS":
				cfg := linuxguest.GuestConfig{Profile: linuxguest.VZ, Name: spec.Name, ControllerID: p.controllerID, RunnerDir: "/opt/actions-runner", BootID: "12345678-1234-1234-1234-123456789abc"}
				report := linuxguest.GuestPreparation{Config: cfg, DNSDHCP: true}
				if kind == "profile" {
					report.Config.Profile = linuxguest.Crosvm
				} else {
					report.DNSReused = true
				}
				r.report, _ = json.Marshal(report)
			case "report-bound":
				r.report = bytes.Repeat([]byte("x"), 4097)
			}
			if err := p.WaitReady(context.Background(), spec.Name); err == nil {
				t.Fatal("invalid Linux readiness admitted")
			}
			for _, call := range r.calls {
				text := strings.Join(call, " ")
				if strings.Contains(text, "seed-jit") || (kind != "profile" && kind != "public-DNS" && kind != "report-bound" && strings.Contains(text, linuxguest.PreparedHelper+" guest")) {
					t.Fatal("unverified helper executed or JIT delivered")
				}
			}
		})
	}
}

type linuxProof struct {
	Runtime
	refused bool
	checks  int
}

func (r *linuxProof) ProveIsolation(string, string) error {
	r.checks++
	if r.refused {
		return errors.New("fixture live proof unavailable")
	}
	return nil
}

func TestLinuxRefusesMissingDurableAndLiveRootlessProofs(t *testing.T) {
	for _, kind := range []string{"record", "record-controller", "record-provider", "record-instance", "marker-provider", "marker-provider-missing", "marker-controller", "policy", "live-proof"} {
		t.Run(kind, func(t *testing.T) {
			p, r, spec := linuxProvider(t)
			bootLinuxFixture(t, p, spec)
			switch kind {
			case "record":
				if err := p.records.Remove("fixture"); err != nil {
					t.Fatal(err)
				}
			case "record-controller":
				p.records, _ = state.Open(t.TempDir(), func() string { return "foreign-controller" })
			case "record-provider":
				if _, err := p.records.Update("fixture", func(i *state.Instance) { i.Provider = "foreign" }); err != nil {
					t.Fatal(err)
				}
			case "record-instance":
				if err := p.records.Remove("fixture"); err != nil {
					t.Fatal(err)
				}
				if err := p.records.Put(&state.Instance{ID: "foreign", Provider: p.name, Name: spec.Name, Phase: state.PhaseCreating}); err != nil {
					t.Fatal(err)
				}
			case "marker-provider", "marker-provider-missing", "marker-controller", "policy":
				meta, _ := p.readMeta(spec.Name)
				switch kind {
				case "marker-provider":
					meta.Provider = "foreign"
				case "marker-provider-missing":
					meta.Provider = ""
				case "marker-controller":
					meta.ControllerID = "foreign"
				case "policy":
					meta.NetworkPolicy = ""
				}
				data, _ := json.Marshal(meta)
				if err := os.WriteFile(filepath.Join(p.vmDir(spec.Name), markerFile), data, 0600); err != nil {
					t.Fatal(err)
				}
			case "live-proof":
				p.rt = &linuxProof{Runtime: p.rt, refused: true}
			}
			before := len(r.calls)
			if err := p.WaitReady(context.Background(), spec.Name); err == nil {
				t.Fatal("readiness skipped proof")
			}
			if err := p.StartRunner(context.Background(), spec.Name, []byte("synthetic-jit")); err == nil {
				t.Fatal("JIT skipped proof")
			}
			if _, err := p.RunnerStatus(context.Background(), spec.Name); err == nil {
				t.Fatal("adoption skipped proof")
			}
			for _, call := range r.calls[before:] {
				if len(call) > 2 && call[0] == "Exec" && call[2] != "true" {
					t.Fatal("unproven Linux guest received command")
				}
			}
		})
	}
}

func TestLinuxCommandsReproveIsolationEveryTime(t *testing.T) {
	p, _, spec := linuxProvider(t)
	bootLinuxFixture(t, p, spec)
	proof := &linuxProof{Runtime: p.rt}
	p.rt = proof
	for _, mode := range []string{"seed-jit", "launch", "status", "cancel", "diagnostics"} {
		before := proof.checks
		if _, err := p.linuxCommand(context.Background(), spec.Name, mode, nil, 4096); err != nil {
			t.Fatal(err)
		}
		if proof.checks <= before {
			t.Fatal("operation skipped fresh isolation proof", mode)
		}
	}
}

func TestLinuxBoundedJITAndStatus(t *testing.T) {
	p, r, spec := linuxProvider(t)
	bootLinuxFixture(t, p, spec)
	for _, jit := range [][]byte{nil, bytes.Repeat([]byte("x"), 128<<10+1)} {
		if err := p.StartRunner(context.Background(), spec.Name, jit); err == nil {
			t.Fatal("invalid JIT bound admitted")
		}
	}
	for _, data := range []string{strings.Repeat("x", 4097), `{}`, `{"State":"unknown"}`, `{"State":"listening","extra":true}`, `{"State":"listening"} {}`, `{"State":"running","Job":{"RunID":0}}`, `{"State":"exited","ExitCode":1000}`} {
		r.status = []byte(data)
		if _, err := p.RunnerStatus(context.Background(), spec.Name); err == nil {
			t.Fatal("invalid Linux status admitted")
		}
	}
	r.status = nil
	r.statusError = errors.New("synthetic transport loss")
	if _, err := p.RunnerStatus(context.Background(), spec.Name); !errors.Is(err, provider.GuestAgentUnavailable) {
		t.Fatal("transport error not classified", err)
	}
	r.vms[spec.Name] = false
	if status, err := p.RunnerStatus(context.Background(), spec.Name); err != nil || status.State != provider.RunnerAbsent {
		t.Fatal("stopped runner not absent", err)
	}
}

func TestLinuxDiagnosticsUseBoundedRedactingSink(t *testing.T) {
	p, r, spec := linuxProvider(t)
	bootLinuxFixture(t, p, spec)
	var data bytes.Buffer
	archive := zip.NewWriter(&data)
	entry, err := archive.Create("runner.log")
	if err != nil {
		t.Fatal(err)
	}
	secret := "ghs_" + strings.Repeat("Q", 40)
	if _, err := io.WriteString(entry, "fixture "+secret); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	r.diagnostics = []byte(base64.StdEncoding.EncodeToString(data.Bytes()))
	dir := t.TempDir()
	if err := p.CollectDiagnostics(context.Background(), spec.Name, dir); err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile(filepath.Join(dir, "runner.log"))
	if err != nil || !bytes.Contains(output, []byte("fixture")) || bytes.Contains(output, []byte(secret)) {
		t.Fatal("diagnostic sink failed", err)
	}
	r.diagnostics = []byte("invalid!")
	if err := p.CollectDiagnostics(context.Background(), spec.Name, t.TempDir()); err == nil {
		t.Fatal("malformed diagnostic stream admitted")
	}
}

func TestVZExactProviderOwnershipAndSlotExemption(t *testing.T) {
	p, r, spec := linuxProvider(t)
	bootLinuxFixture(t, p, spec)
	mac, err := New("macos", p.cfg, GuestRuntime{OS: "darwin"}, p.controllerID, string(p.store), p.rt, nil)
	if err != nil {
		t.Fatal(err)
	}
	owned, foreign, err := mac.List(context.Background())
	if err != nil || len(owned) != 0 || len(foreign) != 1 || !foreign[0].HostLimitExempt {
		t.Fatal("Linux slot exemption/ownership not manifest-proven", err)
	}
	for _, candidate := range []*Provider{mac, {name: "linux-fixture", controllerID: p.controllerID, store: p.store, rt: p.rt}} {
		if _, ok := candidate.owns(spec.Name); ok {
			t.Fatal("wrong provider acquired marker")
		}
		before := len(r.calls)
		if err := candidate.Stop(context.Background(), spec.Name, time.Second); !errors.Is(err, provider.ErrNotOwned) {
			t.Fatal("wrong provider stopped guest", err)
		}
		if err := candidate.Delete(context.Background(), spec.Name); !errors.Is(err, provider.ErrNotOwned) {
			t.Fatal("wrong provider deleted guest", err)
		}
		for _, call := range r.calls[before:] {
			if call[0] == "Stop" || call[0] == "Delete" {
				t.Fatal("wrong provider mutated native guest")
			}
		}
	}
	if err := os.WriteFile(filepath.Join(p.vmDir(spec.Name), "vm.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	_, foreign, err = mac.List(context.Background())
	if err != nil || len(foreign) != 1 || foreign[0].HostLimitExempt {
		t.Fatal("corrupt manifest exempted")
	}
}

func TestRetainedOSLockUsesCloneAndSkipsMissingDirectory(t *testing.T) {
	p, _, spec := linuxProvider(t)
	bootLinuxFixture(t, p, spec)
	writeTestManifest(t, p.vmDir(spec.Baseline), "darwin")
	if err := p.ValidateRetained(spec.Name); err != nil {
		t.Fatal("baseline replacement changed retained OS", err)
	}
	p.runner.OS = "darwin"
	if err := p.ValidateRetained(spec.Name); err == nil {
		t.Fatal("guest OS switch accepted")
	}
	p.runner.OS = "linux"
	if err := os.Remove(filepath.Join(p.vmDir(spec.Name), "vm.json")); err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateRetained(spec.Name); err == nil {
		t.Fatal("missing retained manifest accepted")
	}
	if err := p.ValidateRetained("bivouac-linux-absent"); err != nil {
		t.Fatal("absent clone prevented recovery", err)
	}
}

func TestLinuxIsolationAndRecordAdmissionBeforeMutations(t *testing.T) {
	for _, kind := range []string{"policy", "record"} {
		t.Run(kind, func(t *testing.T) {
			p, r, spec := linuxProvider(t)
			if kind == "policy" {
				p.checkIsolation = func(context.Context) error { return errors.New("fixture policy unavailable") }
			} else {
				p.SetRecords(nil)
			}
			if err := p.Create(context.Background(), spec); err == nil {
				t.Fatal("new clone admitted without proof")
			}
			if len(r.calls) != 0 {
				t.Fatal("refused admission mutated runtime")
			}
		})
	}
	p, r, spec := linuxProvider(t)
	if err := p.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	p.checkIsolation = func(context.Context) error { return errors.New("fixture policy unavailable") }
	before := len(r.calls)
	if err := p.Start(context.Background(), spec.Name, io.Discard); err == nil {
		t.Fatal("start ignored isolation failure")
	}
	if len(r.calls) != before {
		t.Fatal("refused start mutated runtime")
	}
}
