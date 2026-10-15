package perf

import "testing"

func TestWindowsCommitReadWithoutPrivilegeAdjustment(t *testing.T) {
	s, err := NewSampler(t.TempDir()).Sample()
	if err != nil || s.Commit == nil || !s.Commit.valid() {
		t.Fatal("native read-only commit sampling failed", s, err)
	}
	t.Logf("physical: %.2f GiB available / %.2f GiB total; commit: %s", float64(s.AvailableBytes)/(1<<30), float64(s.TotalBytes)/(1<<30), s.Commit)
}
