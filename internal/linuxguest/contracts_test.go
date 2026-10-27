package linuxguest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHelperFingerprintIsExactAndBounded(t *testing.T) {
	hash := strings.Repeat("a", 64)
	for _, value := range []string{hash + "  /tmp/other", hash + "  " + PreparedHelper + "\nextra", strings.Repeat("a", 257), "untrusted", strings.Repeat("b", 64) + "  " + PreparedHelper} {
		if HelperMatches([]byte(value), hash) {
			t.Fatal("unverified helper accepted")
		}
	}
}

func TestPreparationReportRejectsMismatchAndUnprovenDNS(t *testing.T) {
	want := GuestConfig{Profile: Crosvm, Name: "bivouac-linux-1234abcd", ControllerID: "controller", RunnerDir: "/opt/actions-runner", GPU: true}
	r := GuestPreparation{Config: want, DNSReused: true, TotalMS: 1}
	r.Config.BootID = "12345678-1234-1234-1234-123456789abc"
	good, _ := json.Marshal(r)
	if _, err := DecodeGuestPreparation(good, want, true); err != nil {
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
		if _, err := DecodeGuestPreparation(b, want, true); err == nil {
			t.Fatal("invalid readiness report accepted", kind)
		}
	}
	if _, err := DecodeGuestPreparation(append(good, []byte(" {}")...), want, true); err == nil {
		t.Fatal("multiple reports accepted")
	}
	if _, err := DecodeGuestPreparation([]byte(strings.Replace(string(good), "{", "{\"unknown\":true,", 1)), want, true); err == nil {
		t.Fatal("unknown report fields accepted")
	}
}
