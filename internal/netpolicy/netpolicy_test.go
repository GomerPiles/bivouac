package netpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func prefixStrings(prefixes []netip.Prefix) []string {
	texts := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		texts[i] = prefix.String()
	}
	return texts
}

func TestReservedReturnsIndependentCanonicalCopy(t *testing.T) {
	reserved := Reserved()
	if !slices.Contains(reserved, netip.MustParsePrefix("192.88.99.0/24")) {
		t.Fatal("deprecated 6to4 relay range missing")
	}
	if !slices.Equal(reserved, Reduce(reserved)) {
		t.Fatal("reserved list is not canonical")
	}
	want := slices.Clone(reserved)
	reserved[0] = netip.MustParsePrefix("8.8.8.0/24")
	if !slices.Equal(Reserved(), want) {
		t.Fatal("caller mutation changed the reserved list")
	}
}

func TestReduceCanonicalIPv4(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("8.8.8.9/24"), netip.MustParsePrefix("8.8.8.0/24"),
		netip.MustParsePrefix("8.8.8.10/32"), netip.MustParsePrefix("11.0.0.1/24"),
		netip.MustParsePrefix("192.0.0.1/8"), netip.MustParsePrefix("2001:db8::1/64"), {},
	}
	prefixes = append(prefixes, Reserved()...)
	original := slices.Clone(prefixes)
	want := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "11.0.0.0/24", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/8", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "8.8.8.0/24"}
	if got := prefixStrings(Reduce(prefixes)); !slices.Equal(got, want) {
		t.Fatalf("reduced prefixes = %v, want %v", got, want)
	}
	if !slices.Equal(prefixes, original) {
		t.Fatal("reduction modified the input")
	}
	if got := Reduce(nil); len(got) != 0 {
		t.Fatalf("empty reduction added prefixes: %v", got)
	}
}

func TestRustReservedMatchesGo(t *testing.T) {
	source, err := os.ReadFile("../../tools/crosvm/public_ipv4.rs")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`const\s+RESERVED:\s*&str\s*=\s*"([^"]*)"\s*;`).FindSubmatch(source)
	if match == nil {
		t.Fatal("cannot find RESERVED string literal in tools/crosvm/public_ipv4.rs")
	}
	want := strings.Join(prefixStrings(Reserved()), ",")
	if got := string(match[1]); got != want {
		t.Fatalf("Rust RESERVED = %q, want netpolicy.Reserved() = %q", got, want)
	}
}

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
	for _, hosts := range [][]netip.Prefix{nil, {{}}, {netip.MustParsePrefix("0.0.0.0/0")}, {netip.MustParsePrefix("::/0")}, {netip.MustParsePrefix("10.0.0.1/24"), {}}} {
		if _, _, err := BlockedPrefixes(hosts); err == nil {
			t.Fatal("invalid inventory accepted")
		}
		if _, _, err := EffectiveDenial(hosts); err == nil {
			t.Fatal("invalid inventory accepted by effective denial")
		}
	}
}

func TestEffectiveDenialDeliversReservedAndPublicHostPrefixes(t *testing.T) {
	hosts := []netip.Prefix{netip.MustParsePrefix("192.168.1.7/24"), netip.MustParsePrefix("192.88.99.1/32"), netip.MustParsePrefix("fe80::1/64")}
	effective, _, err := EffectiveDenial(hosts)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(effective, Reserved()) {
		t.Fatalf("covered inventory produced %v, want Reserved()", effective)
	}
	effective, snapshot, err := EffectiveDenial(append(hosts, netip.MustParsePrefix("8.8.8.10/24")))
	if err != nil {
		t.Fatal(err)
	}
	want := append(Reserved(), netip.MustParsePrefix("8.8.8.0/24"))
	if !slices.Equal(effective, want) {
		t.Fatalf("public inventory produced %v, want %v", effective, want)
	}
	hash := sha256.Sum256([]byte(strings.Join(prefixStrings(want), "\n")))
	if snapshot != hex.EncodeToString(hash[:]) {
		t.Fatal("snapshot differs from SHA-256 of newline-joined canonical prefixes")
	}
}

func TestEffectiveDenialBound(t *testing.T) {
	var hosts []netip.Prefix
	for i := 0; i < 128-len(Reserved()); i++ {
		hosts = append(hosts, netip.PrefixFrom(netip.AddrFrom4([4]byte{11, 0, 0, byte(i)}), 32))
	}
	if effective, _, err := EffectiveDenial(hosts); err != nil || len(effective) != 128 {
		t.Fatalf("128 effective prefixes refused: count=%d, error=%v", len(effective), err)
	}
	hosts = append(hosts, netip.MustParsePrefix("8.8.8.8/32"))
	if _, _, err := EffectiveDenial(hosts); err == nil {
		t.Fatal("more than 128 effective prefixes accepted")
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
