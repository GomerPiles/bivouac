// Package macnetwork defines the effective network denial for guests on macOS hosts.
package macnetwork

import (
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
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
	var prefixes []netip.Prefix
	for _, r := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		prefixes = append(prefixes, netip.MustParsePrefix(r))
	}
	for _, p := range local {
		if p.Addr().Is4() {
			prefixes = append(prefixes, p.Masked())
		}
	}
	rules := make([]string, 0, len(prefixes))
	for i, p := range prefixes {
		covered := false
		for j, q := range prefixes {
			if i != j && q.Bits() <= p.Bits() && q.Contains(p.Addr()) && (q != p || j < i) {
				covered = true
				break
			}
		}
		if !covered {
			rules = append(rules, p.String())
		}
	}
	sort.Strings(rules)
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
