package crosvm

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

type startupFixture struct {
	probe                    []byte
	failure                  error
	uploads, chmod, prepares int
	path                     string
	bad                      bool
}

func (f *startupFixture) Output(_ context.Context, binary string, args []string) ([]byte, error) {
	if binary == "scp" {
		f.uploads++
		return nil, nil
	}
	if strings.Contains(strings.Join(args, " "), "chmod 700 bivouac-guest") {
		f.chmod++
		return nil, nil
	}
	return nil, errors.New("unexpected startup command")
}
func (f *startupFixture) OutputLimit(context.Context, string, []string, int) ([]byte, error) {
	return nil, errors.New("unexpected startup output")
}
func (f *startupFixture) Input(_ context.Context, _ string, args []string, input []byte) ([]byte, error) {
	if string(input) == preparedHelperProbe {
		return f.probe, f.failure
	}
	if args[len(args)-1] != "prepare" {
		return nil, errors.New("unexpected startup input")
	}
	f.prepares++
	f.path = args[len(args)-4]
	var cfg GuestConfig
	if json.Unmarshal(input, &cfg) != nil {
		return nil, errors.New("invalid fixture config")
	}
	cfg.BootID = "12345678-1234-1234-1234-123456789abc"
	if f.bad {
		cfg.Name = "foreign"
	}
	return json.Marshal(GuestPreparation{Config: cfg, DNSReused: true, TotalMS: 1})
}
func TestPreparedHelperReuseAndFallback(t *testing.T) {
	for _, kind := range []string{"match", "missing", "different", "transport", "bad-report"} {
		t.Run(kind, func(t *testing.T) {
			_, r := fixture(t)
			hash := strings.Repeat("a", 64)
			f := &startupFixture{probe: []byte(hash + "  " + preparedHelper + "\n")}
			switch kind {
			case "missing":
				f.probe = []byte("absent\n")
			case "different":
				f.probe = []byte(strings.Repeat("b", 64) + "  " + preparedHelper + "\n")
			case "transport":
				f.failure = errors.New("synthetic transport failure")
			case "bad-report":
				f.bad = true
			}
			g := &SSHGuest{opts: SSHOptions{StateDir: filepath.Join(t.TempDir(), "ssh"), Helper: "fixture-helper", User: "ciuser"}, ssh: "ssh", scp: "scp", commands: f, helperSHA256: hash}
			err := g.Ready(context.Background(), r)
			if (err != nil) != (kind == "transport" || kind == "bad-report") {
				t.Fatal("readiness result differs", err)
			}
			if kind == "transport" {
				if f.uploads+f.prepares != 0 {
					t.Fatal("transport failure caused mutation")
				}
				return
			}
			if kind == "match" || kind == "bad-report" {
				if f.uploads+f.chmod != 0 || f.path != preparedHelper {
					t.Fatal("matching helper was uploaded or wrong helper ran")
				}
			} else if f.uploads != 1 || f.chmod != 1 || f.path != "./bivouac-guest" {
				t.Fatal("fallback did not use fresh uploaded helper")
			}
		})
	}
}
func TestHelperFingerprintIsExactAndBounded(t *testing.T) {
	hash := strings.Repeat("a", 64)
	for _, value := range []string{hash + "  /tmp/other", hash + "  " + preparedHelper + "\nextra", strings.Repeat("a", 257), "untrusted", strings.Repeat("b", 64) + "  " + preparedHelper} {
		if helperMatches([]byte(value), hash) {
			t.Fatal("unverified helper accepted")
		}
	}
}

func TestPreparationReportRejectsMismatchAndUnprovenDNS(t *testing.T) {
	want := GuestConfig{Name: "bivouac-linux-1234abcd", ControllerID: "controller", RunnerDir: "/opt/actions-runner", GPU: true}
	r := GuestPreparation{Config: want, DNSReused: true, TotalMS: 1}
	r.Config.BootID = "12345678-1234-1234-1234-123456789abc"
	good, _ := json.Marshal(r)
	if _, err := decodeGuestPreparation(good, want, true); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"identity", "negative", "overflow", "dns-contradiction", "dns-not-reused", "failed-stage"} {
		bad := r
		switch kind {
		case "identity":
			bad.Config.ControllerID = "foreign"
		case "negative":
			bad.DNSMS = -1
		case "overflow":
			bad.TotalMS = 720001
		case "dns-contradiction":
			bad.DNSProfileChanged = true
		case "dns-not-reused":
			bad.DNSReused = false
		case "failed-stage":
			bad.FailedStage = 6
			bad.DNSFailure = 8
		}
		b, _ := json.Marshal(bad)
		if _, err := decodeGuestPreparation(b, want, true); err == nil {
			t.Fatal("invalid readiness report accepted", kind)
		}
	}
	if _, err := decodeGuestPreparation(append(good, []byte(" {}")...), want, true); err == nil {
		t.Fatal("multiple reports accepted")
	}
	if _, err := decodeGuestPreparation([]byte(strings.Replace(string(good), "{", "{\"unknown\":true,", 1)), want, true); err == nil {
		t.Fatal("unknown report fields accepted")
	}
}
