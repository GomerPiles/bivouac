// Package cachelink defines the fixed cache capabilities on the virtual link.
// This address is synthesized inside the userspace stack, never a host alias.
package cachelink

const Address = "192.0.2.1"
const Port = 7443
const Endpoint = "192.0.2.1:7443"

// DefaultMaxConnections is the host endpoint and parent payload bound.
const DefaultMaxConnections = 256

// Revocation is public signed PKI data, with a budget independent of payload
// TLS handshakes. Neither endpoint is an alias for host-network access.
const RevocationPort = 7444
const RevocationEndpoint = "192.0.2.1:7444"
const RevocationURL = "http://192.0.2.1:7444/ca.crl"
const MaxRevocationConnections = 32

type Kind byte

const (
	Payload    Kind = 1
	Revocation Kind = 2
)
