package provider

import "testing"

func TestTransportFailureRetryable(t *testing.T) {
	for _, f := range []TransportFailure{SSHUnavailable, SSHTimeout, SSHRefused, SSHReset, SSHClosed, GuestAgentUnavailable, GuestAgentTimeout} {
		if !f.Retryable() {
			t.Errorf("%v: want retryable", f)
		}
	}
	for _, f := range []TransportFailure{SSHAuthentication, SSHHostKey, SSHConfiguration, SSHDiagnosticLimit} {
		if f.Retryable() {
			t.Errorf("%v: want terminal", f)
		}
	}
}
