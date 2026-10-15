package crosvm

import "testing"

func TestDNSSelectsOnlyOneValidUplinkProfile(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc"
	got, err := uplinkProfile([]byte(id + ":eth0\n22345678-1234-1234-1234-123456789abc:docker0\n"))
	if err != nil || got != id {
		t.Fatal("uplink selection failed")
	}
	for _, value := range []string{"", id + ":docker0", id + ":eth0\n" + id + ":eth0", "not-a-uuid:eth0", "malformed", "123456781234-1234-1234-1234-12345678:eth0"} {
		if _, err := uplinkProfile([]byte(value)); err == nil {
			t.Fatal("unsafe/ambiguous uplink accepted")
		}
	}
}
