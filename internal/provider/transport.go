package provider

// TransportFailure contains only a fixed classification, never command output,
// arguments or credentials. Providers emit it only after ownership/isolation
// checks, for a failed guest transport. Unknown errors are terminal by default.
type TransportFailure uint8

// Retryable classes come first, through GuestAgentTimeout; Retryable relies
// on that order.
const (
	SSHUnavailable TransportFailure = iota
	SSHTimeout
	SSHRefused
	SSHReset
	SSHClosed
	// GuestAgentUnavailable and GuestAgentTimeout are failures of a non-SSH
	// guest channel, such as the Tart guest agent behind `tart exec`.
	GuestAgentUnavailable
	GuestAgentTimeout
	SSHAuthentication
	SSHHostKey
	SSHConfiguration
	SSHDiagnosticLimit
)

func (e TransportFailure) Error() string {
	switch e {
	case SSHTimeout:
		return "SSH transport timeout"
	case SSHRefused:
		return "SSH connection refused"
	case SSHReset:
		return "SSH connection reset"
	case SSHClosed:
		return "SSH connection closed"
	case GuestAgentUnavailable:
		return "guest agent unavailable"
	case GuestAgentTimeout:
		return "guest agent timeout"
	case SSHAuthentication:
		return "SSH authentication failed"
	case SSHHostKey:
		return "SSH host key verification failed"
	case SSHConfiguration:
		return "SSH transport configuration failed"
	case SSHDiagnosticLimit:
		return "SSH failure diagnostics exceeded bound"
	default:
		return "SSH transport unavailable"
	}
}

func (e TransportFailure) Retryable() bool {
	return e <= GuestAgentTimeout
}
