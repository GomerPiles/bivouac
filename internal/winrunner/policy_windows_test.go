package winrunner

import "testing"

func TestRunnerExecutionPolicyOnlyLoosensARefusingGuest(t *testing.T) {
	for _, c := range []struct {
		inherited bool
		machine   string
		want      string
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
		if got := runnerExecutionPolicy(c.inherited, c.machine); got != c.want {
			t.Errorf("inherited=%v machine=%q: got %q, want %q", c.inherited, c.machine, got, c.want)
		}
	}
}
