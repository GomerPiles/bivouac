// Package linuxguest owns the fixed Linux runner runtime and its bounded wire
// contracts. Providers own transports, VM lifetimes and host admission proofs.
package linuxguest

import "errors"

// ExecutionProfile is carried by bootstrap stdin, persisted with the boot
// identity, and repeated in image requests/receipts. Empty/unknown profiles fail
// closed; independently executed commands must not infer policy from the host.
type ExecutionProfile string

const (
	Crosvm ExecutionProfile = "crosvm-public-dns-ssh"
	VZ     ExecutionProfile = "vz-dhcp"
)

func (p ExecutionProfile) Validate() error {
	switch p {
	case Crosvm, VZ:
		return nil
	default:
		return errors.New("invalid Linux execution profile")
	}
}

// prepareDNS leaves DHCP configuration and resolver files entirely untouched
// for VZ. DHCP delegation is not evidence of public resolver reuse.
func (p ExecutionProfile) prepareDNS(public func() (dnsPreparation, error)) (dnsPreparation, error) {
	switch p {
	case Crosvm:
		return public()
	case VZ:
		return dnsPreparation{DHCP: true}, nil
	default:
		return dnsPreparation{}, p.Validate()
	}
}

// SSH paths and key-generation units belong only to the SSH transport profile.
func (p ExecutionProfile) sshSanitation() bool { return p == Crosvm }
