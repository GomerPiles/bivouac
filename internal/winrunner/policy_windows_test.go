package winrunner

import "testing"

func TestRunnerExecutionPolicyOnlyLoosensARefusingGuest(t *testing.T) {
	for _, c := range []struct {
		inherited  bool
		configured string
		want       string
	}{
		{false, "", "RemoteSigned"},
		{false, "Restricted", "RemoteSigned"},
		{false, "AllSigned", "RemoteSigned"},
		{false, "Undefined", "RemoteSigned"},
		{false, "RemoteSigned", ""},
		{false, "Unrestricted", ""},
		{false, "Bypass", ""},
		{true, "Restricted", ""},
	} {
		if got := runnerExecutionPolicy(c.inherited, c.configured); got != c.want {
			t.Errorf("inherited=%v configured=%q: got %q, want %q", c.inherited, c.configured, got, c.want)
		}
	}
}
