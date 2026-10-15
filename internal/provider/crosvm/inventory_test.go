package crosvm

import (
	"net/netip"
	"slices"
	"testing"
)

func TestDenialInventoryPreservesPublicBoundaryAcrossAdapterChurn(t *testing.T) {
	base := []netip.Prefix{netip.MustParsePrefix("10.0.0.7/16"), netip.MustParsePrefix("100.100.1.2/32"), netip.MustParsePrefix("8.8.8.7/24")}
	frozen, snapshot, err := denialInventory(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, added := range []string{"172.31.112.1/28", "192.168.42.1/24", "127.0.0.1/8", "8.8.8.8/32", "fd00::1/64", "2001:4860::1/64"} {
		prefixes, next, err := denialInventory(append(slices.Clone(base), netip.MustParsePrefix(added)))
		if err != nil || next != snapshot || !slices.Equal(prefixes, frozen) {
			t.Fatalf("already denied adapter %s changed the boundary: %v", added, err)
		}
	}
	for _, added := range []string{"9.9.9.1/24", "10.0.0.1/4", "8.8.8.1/16"} {
		_, next, err := denialInventory(append(slices.Clone(base), netip.MustParsePrefix(added)))
		if err != nil || next == snapshot {
			t.Fatalf("expanded public boundary %s was ignored: %v", added, err)
		}
	}
	_, next, err := denialInventory([]netip.Prefix{netip.MustParsePrefix("10.0.0.8/16")})
	if err != nil || next == snapshot {
		t.Fatal("removed public denial must trigger retirement")
	}
	for _, bad := range [][]netip.Prefix{nil, {netip.Prefix{}}, {netip.MustParsePrefix("0.0.0.0/0")}} {
		if _, _, err := denialInventory(bad); err == nil {
			t.Fatal("invalid interface inventory admitted")
		}
	}
}
