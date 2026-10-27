package macnetwork

import (
	"net/netip"
	"testing"
)

func TestDoctorPublicReachability(t *testing.T) {
	for _, count := range []int{0, 1, 3} {
		i := 0
		got := PublicReachability(func(netip.Addr) bool { i++; return i <= count })
		want := map[int]string{0: "FAIL", 1: "WARN", 3: "PASS"}[count]
		if got != want {
			t.Fatal("incorrect public admission result")
		}
	}
}
