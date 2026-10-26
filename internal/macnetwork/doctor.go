package macnetwork

import "net/netip"

// PublicReachability checks several unrelated public prefixes without probing.
// It detects conservative split-default denial without assuming one address
// represents the whole Internet.
func PublicReachability(allow func(netip.Addr) bool) string {
	admitted := 0
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"} {
		if allow(netip.MustParseAddr(s)) {
			admitted++
		}
	}
	if admitted == 0 {
		return "FAIL"
	}
	if admitted < 3 {
		return "WARN"
	}
	return "PASS"
}
