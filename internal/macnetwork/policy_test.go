package macnetwork

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/netpolicy"
)

func TestPolicyWithoutLocalPrefixesEqualsReserved(t *testing.T) {
	var reserved []string
	for _, prefix := range netpolicy.Reserved() {
		reserved = append(reserved, prefix.String())
	}
	if got, want := policyFromPrefixes(nil), strings.Join(reserved, ","); got != want {
		t.Fatalf("policy = %q, want %q", got, want)
	}
	if Allows(policyFromPrefixes(nil), netip.MustParseAddr("192.88.99.1")) {
		t.Fatal("deprecated 6to4 relay address admitted")
	}
}

func TestPublicOnlyWithLocalPublicNetworks(t *testing.T) {
	policy := policyFromPrefixes([]netip.Prefix{netip.MustParsePrefix("11.22.33.7/24"), netip.MustParsePrefix("12.34.56.7/32")})
	for _, address := range []string{"0.1.2.3", "10.0.0.1", "100.64.1.2", "127.0.0.1", "169.254.169.254", "172.16.1.2", "192.0.0.9", "192.168.1.2", "198.18.0.1", "224.0.0.1", "255.255.255.255", "11.22.33.7", "11.22.33.99", "12.34.56.7", "::1", "fe80::1", "fd00::1", "2606:4700:4700::1111"} {
		if Allows(policy, netip.MustParseAddr(address)) {
			t.Errorf("admitted prohibited address %s", address)
		}
	}
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "11.22.34.1", "12.34.56.8"} {
		if !Allows(policy, netip.MustParseAddr(address)) {
			t.Errorf("denied public address %s", address)
		}
	}
}
func TestPolicyCanonicalAndMaskChangesDetected(t *testing.T) {
	base := policyFromPrefixes([]netip.Prefix{netip.MustParsePrefix("11.22.33.7/24")})
	churn := policyFromPrefixes([]netip.Prefix{netip.MustParsePrefix("10.1.2.3/24"), netip.MustParsePrefix("11.22.33.8/32"), netip.MustParsePrefix("11.22.33.9/24")})
	if base != churn {
		t.Fatal("redundant private interfaces or aliases changed effective policy")
	}
	broader := policyFromPrefixes([]netip.Prefix{netip.MustParsePrefix("11.22.33.7/16")})
	if base == broader || Allows(broader, netip.MustParseAddr("11.22.34.1")) {
		t.Fatal("broader local network was missed")
	}
	for _, invalid := range []string{"", "@host", "bad-policy"} {
		if Allows(invalid, netip.MustParseAddr("1.1.1.1")) {
			t.Fatal("missing, obsolete or malformed policy failed open")
		}
	}
}
