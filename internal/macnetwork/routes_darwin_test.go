package macnetwork

import (
	"net/netip"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestConnectedPublicRoutesAndPointToPointPeer(t *testing.T) {
	addresses := func(dst, mask [4]byte) []route.Addr {
		return []route.Addr{unix.RTAX_DST: &route.Inet4Addr{IP: dst}, unix.RTAX_NETMASK: &route.Inet4Addr{IP: mask}}
	}
	publicDefault := addresses([4]byte{}, [4]byte{})
	publicDefault[unix.RTAX_GATEWAY] = &route.Inet4Addr{IP: [4]byte{14, 22, 33, 1}}
	messages := []route.Message{
		&route.RouteMessage{Flags: unix.RTF_UP, Addrs: addresses([4]byte{11, 22, 33, 0}, [4]byte{255, 255, 255, 0})},
		&route.RouteMessage{Flags: unix.RTF_UP | unix.RTF_HOST, Addrs: addresses([4]byte{12, 34, 56, 7}, [4]byte{})},
		&route.RouteMessage{Flags: unix.RTF_UP | unix.RTF_GATEWAY, Addrs: publicDefault},
		&route.RouteMessage{Flags: unix.RTF_UP | unix.RTF_GATEWAY, Addrs: addresses([4]byte{13, 22, 33, 0}, [4]byte{255, 255, 255, 0})},
		&route.RouteMessage{Flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_DYNAMIC, Addrs: addresses([4]byte{8, 8, 8, 8}, [4]byte{})},
		&route.RouteMessage{Flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_WASCLONED, Addrs: addresses([4]byte{1, 1, 1, 1}, [4]byte{})},
	}
	prefixes, err := connectedPrefixes(messages)
	if err != nil || len(prefixes) != 4 {
		t.Fatalf("connected routes: %v, count %d", err, len(prefixes))
	}
	policy := policyFromPrefixes(prefixes)
	if Allows(policy, netip.MustParseAddr("11.22.33.99")) || Allows(policy, netip.MustParseAddr("12.34.56.7")) || Allows(policy, netip.MustParseAddr("13.22.33.9")) || Allows(policy, netip.MustParseAddr("14.22.33.1")) {
		t.Fatal("connected/routed public destination admitted")
	}
	if !Allows(policy, netip.MustParseAddr("1.1.1.1")) || !Allows(policy, netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("default or cloned route blocked public traffic")
	}
}

func TestHostSnapshotSafeUnderRaceChecking(t *testing.T) {
	for range 16 {
		if _, err := Policy(); err != nil {
			t.Fatalf("read-only host policy snapshot failed: %v", err)
		}
	}
}
