package macnetwork

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestAdmissionSnapshotIsSharedAndRefreshFailureDenies(t *testing.T) {
	now := time.Now()
	calls := 0
	failing := false
	c := &Cache{now: func() time.Time { return now }, read: func() (string, error) {
		calls++
		if failing {
			return "", errors.New("fixture failure")
		}
		return policyFromPrefixes(nil), nil
	}}
	for range 10000 {
		if !c.Allows(netip.MustParseAddr("1.1.1.1")) {
			t.Fatal("public control refused")
		}
	}
	if calls != 1 {
		t.Fatalf("snapshot rebuilt %d times", calls)
	}
	now = now.Add(RefreshInterval)
	failing = true
	if c.Allows(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("refresh failure retained stale success")
	}
	if calls != 2 {
		t.Fatal("snapshot did not refresh")
	}
	now = now.Add(RefreshInterval)
	failing = false
	if !c.Allows(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("fresh successful snapshot did not recover")
	}
}

func BenchmarkCachedAdmission(b *testing.B) {
	c := NewCache()
	calls := 0
	c.read = func() (string, error) { calls++; return Policy() }
	address := netip.MustParseAddr("1.1.1.1")
	_ = c.Allows(address)
	b.ResetTimer()
	for range b.N {
		_ = c.Allows(address)
	}
	b.StopTimer()
	b.ReportMetric(float64(calls), "snapshots")
}
