// Package macnetwork defines the effective network denial for guests on macOS hosts.
package macnetwork

import (
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/GomerPiles/bivouac/internal/netpolicy"
)

// Policy includes every local IPv4 address/subnet (including public
// addresses), explicit routed subnets, and private/reserved space. Virtual
// gateway services are implemented inside rootnet, never forwarded to the host.
func Policy() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	var prefixes []netip.Prefix
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				return "", errors.New("unrecognised host interface address")
			}
			prefixes = append(prefixes, p)
		}
	}
	routes, err := connectedRoutes()
	if err != nil {
		return "", err
	}
	return policyFromPrefixes(append(prefixes, routes...)), nil
}

func policyFromPrefixes(local []netip.Prefix) string {
	prefixes := netpolicy.Reduce(append(netpolicy.Reserved(), local...))
	rules := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		rules[i] = prefix.String()
	}
	return strings.Join(rules, ",")
}

func Allows(policy string, address netip.Addr) bool {
	if !address.Is4() {
		return false
	}
	for _, rule := range strings.Split(policy, ",") {
		p, err := netip.ParsePrefix(rule)
		if err != nil || p.Contains(address) {
			return false
		}
	}
	return true
}
