package netpolicy

import (
	"net/netip"
	"slices"
	"testing"
)

func TestPublicHostPrefixesAndInterfaceIdentityAreDenied(t *testing.T) {
	hosts := []netip.Prefix{netip.MustParsePrefix("8.8.8.10/24"), netip.MustParsePrefix("192.168.1.7/24"), netip.MustParsePrefix("2001:db8::1/64")}
	blocks, snapshot, err := BlockedPrefixes(hosts)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"8.8.8.0/24", "192.168.1.0/24", "169.254.0.0/16", "100.64.0.0/10", "240.0.0.0/4"} {
		if !slices.Contains(blocks, want) {
			t.Errorf("missing %s", want)
		}
	}
	slices.Reverse(hosts)
	_, reordered, err := BlockedPrefixes(hosts)
	if err != nil || reordered != snapshot {
		t.Fatal("ordering changed interface identity")
	}
	hosts[0] = netip.MustParsePrefix("2001:db8::2/64")
	_, changed, err := BlockedPrefixes(hosts)
	if err != nil || changed == snapshot {
		t.Fatal("IPv6 interface change was ignored")
	}
	hosts[2] = netip.MustParsePrefix("8.8.8.11/24")
	_, changedAgain, err := BlockedPrefixes(hosts)
	if err != nil || changedAgain == changed {
		t.Fatal("same-subnet host address change was ignored")
	}
}

func TestMissingOrInvalidHostInventoryFailsClosed(t *testing.T) {
	for _, hosts := range [][]netip.Prefix{nil, {{}}, {netip.MustParsePrefix("0.0.0.0/0")}} {
		if _, _, err := BlockedPrefixes(hosts); err == nil {
			t.Fatal("invalid inventory accepted")
		}
	}
}

func TestEffectiveDenialIgnoresCoveredPrivateAdapters(t *testing.T) {
	hosts := []netip.Prefix{netip.MustParsePrefix("192.168.1.7/24"), netip.MustParsePrefix("8.8.8.10/24")}
	_, base, err := EffectiveDenial(hosts)
	if err != nil {
		t.Fatal(err)
	}
	withGuestSwitch := append(slices.Clone(hosts), netip.MustParsePrefix("10.251.0.1/28"), netip.MustParsePrefix("fe80::1/64"))
	if _, snapshot, err := EffectiveDenial(withGuestSwitch); err != nil || snapshot != base {
		t.Fatal("a covered private adapter changed the effective denial", err)
	}
	withPublic := append(slices.Clone(hosts), netip.MustParsePrefix("203.0.114.9/24"))
	if _, snapshot, err := EffectiveDenial(withPublic); err != nil || snapshot == base {
		t.Fatal("a new public prefix did not change the effective denial", err)
	}
}
