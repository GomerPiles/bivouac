package linuxguest

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfilesSelectDNSBehavior(t *testing.T) {
	for _, profile := range []ExecutionProfile{Crosvm, VZ, "", "unknown"} {
		called := false
		fault := errors.New("synthetic public DNS failure")
		r, err := profile.prepareDNS(func() (dnsPreparation, error) { called = true; return dnsPreparation{}, fault })
		switch profile {
		case Crosvm:
			if !called || !errors.Is(err, fault) {
				t.Fatal("Crosvm did not retain public DNS preparation")
			}
		case VZ:
			if called || err != nil || !r.DHCP || r.Reused || r.ProfileChanged || r.ResolverChanged {
				t.Fatal("DHCP profile rewrote DNS or claimed public DNS reuse")
			}
		default:
			if err == nil || called {
				t.Fatal("invalid profile reached guest commands")
			}
		}
	}
}

func TestPreparationReportsBindProfileAndDNS(t *testing.T) {
	for _, profile := range []ExecutionProfile{Crosvm, VZ} {
		want := GuestConfig{Profile: profile, Name: "bivouac-linux-1234abcd", ControllerID: "controller", RunnerDir: "/opt/actions-runner"}
		report := GuestPreparation{Config: want, DNSReused: profile == Crosvm, DNSDHCP: profile == VZ, TotalMS: 1}
		report.Config.BootID = "12345678-1234-1234-1234-123456789abc"
		b, _ := json.Marshal(report)
		if _, err := DecodeGuestPreparation(b, want, true); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"profile", "dhcp", "dns-reuse"} {
			bad := report
			switch kind {
			case "profile":
				bad.Config.Profile = "unknown"
			case "dhcp":
				bad.DNSDHCP = !bad.DNSDHCP
			case "dns-reuse":
				bad.DNSReused = !bad.DNSReused
			}
			b, _ := json.Marshal(bad)
			if _, err := DecodeGuestPreparation(b, want, true); err == nil {
				t.Fatal("contradictory report admitted", profile, kind)
			}
		}
	}
}

func TestImageReceiptsBindProfileAndSanitation(t *testing.T) {
	hash := strings.Repeat("a", 64)
	for _, profile := range []ExecutionProfile{Crosvm, VZ} {
		report := PreparedLinuxImage{Profile: profile, HelperSHA256: hash, RunnerUnconfigured: true, MachineIDCleared: true, DNSPrepared: profile == Crosvm, DNSDHCP: profile == VZ, SSHHostKeysRemoved: profile == Crosvm}
		b, _ := json.Marshal(report)
		if _, err := DecodePreparedImage(b, profile, hash); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"profile", "hash", "ssh", "dns", "dhcp", "failure"} {
			bad := report
			switch kind {
			case "profile":
				bad.Profile = ""
			case "hash":
				bad.HelperSHA256 = strings.Repeat("b", 64)
			case "ssh":
				bad.SSHHostKeysRemoved = !bad.SSHHostKeysRemoved
			case "dns":
				bad.DNSPrepared = !bad.DNSPrepared
			case "dhcp":
				bad.DNSDHCP = !bad.DNSDHCP
			case "failure":
				bad.FailedStage = 8
			}
			b, _ := json.Marshal(bad)
			if _, err := DecodePreparedImage(b, profile, hash); err == nil {
				t.Fatal("invalid image receipt admitted", profile, kind)
			}
		}
		for _, bad := range [][]byte{append(b, []byte(" {}")...), []byte(`{"unknown":true}`), make([]byte, 4097)} {
			if _, err := DecodePreparedImage(bad, profile, hash); err == nil {
				t.Fatal("invalid bounded image receipt admitted")
			}
		}
	}
}

func TestHelperFileFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	hash, err := HelperSHA256(path)
	if err != nil || hash != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("wrong helper fingerprint", err)
	}
	if _, err := HelperSHA256(path + "-missing"); err == nil {
		t.Fatal("missing helper accepted")
	}
}

// Compile-time contract keeps the guest's command seam argument-array based.
var _ guestCommands = noCommands{}

type noCommands struct{}

func (noCommands) Output(context.Context, string, []string) ([]byte, error) {
	return nil, errors.New("unexpected command")
}
func (noCommands) OutputLimit(context.Context, string, []string, int) ([]byte, error) {
	return nil, errors.New("unexpected command")
}
func (noCommands) Input(context.Context, string, []string, []byte) ([]byte, error) {
	return nil, errors.New("unexpected command")
}
