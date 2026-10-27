//go:build !darwin

package macnetwork

import "net/netip"

// macOS policy is also compiled in portable tests and the guest helper.
func connectedRoutes() ([]netip.Prefix, error) { return nil, nil }
