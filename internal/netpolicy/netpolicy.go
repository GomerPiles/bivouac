// Package netpolicy defines reserved IPv4 prefixes and canonical egress denials
// shared by every provider, independently of how a provider enforces them.
package netpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strings"
)

// Reserved returns a fresh, canonically sorted list of non-public IPv4 ranges.
// It includes the deprecated 6to4 relay anycast range (RFC 7526).
func Reserved() []netip.Prefix {
	texts := strings.Fields("0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 192.88.99.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4")
	prefixes := make([]netip.Prefix, len(texts))
	for i, text := range texts {
		prefixes[i] = netip.MustParsePrefix(text)
	}
	return prefixes
}

// Reduce masks valid IPv4 prefixes, removes duplicates and prefixes covered by
// broader inputs, and sorts by Prefix.String. It does not modify the input or
// add reserved ranges; callers include Reserved when needed.
func Reduce(prefixes []netip.Prefix) []netip.Prefix {
	var masked []netip.Prefix
	for _, prefix := range prefixes {
		if prefix.IsValid() && prefix.Addr().Is4() {
			masked = append(masked, prefix.Masked())
		}
	}
	slices.SortFunc(masked, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	masked = slices.Compact(masked)
	var reduced []netip.Prefix
	for _, prefix := range masked {
		covered := false
		for _, outer := range masked {
			if outer.Bits() < prefix.Bits() && outer.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			reduced = append(reduced, prefix)
		}
	}
	return reduced
}

// BlockedPrefixes includes non-public ranges and every host interface's
// connected prefix (including public addresses). IPv6 is separately denied
// entirely by the Windows providers. The returned snapshot identifies the host
// interface inventory, so a caller can refuse a policy that changed during a job.
func BlockedPrefixes(host []netip.Prefix) ([]string, string, error) {
	var result []string
	for _, prefix := range Reserved() {
		result = append(result, prefix.String())
	}
	var identities []string
	for _, prefix := range host {
		if !prefix.IsValid() || prefix.Bits() == 0 {
			return nil, "", errors.New("invalid host interface prefix")
		}
		identities = append(identities, prefix.String())
		if prefix.Addr().Is4() {
			result = append(result, prefix.Masked().String())
		}
	}
	if len(identities) == 0 {
		return nil, "", errors.New("cannot inventory host interfaces")
	}
	slices.Sort(result)
	result = slices.Compact(result)
	slices.Sort(identities)
	identities = slices.Compact(identities)
	hash := sha256.Sum256([]byte(strings.Join(identities, "\n")))
	return result, hex.EncodeToString(hash[:]), nil
}

// EffectiveDenial reduces BlockedPrefixes to the prefixes no broader denial
// already covers, and identifies that set. A new private adapter whose prefix
// is already denied, such as another guest's switch, cannot expand guest
// access and leaves the snapshot unchanged; a new public prefix changes it.
// IPv6 is denied entirely elsewhere, so IPv6 addresses never change it.
func EffectiveDenial(host []netip.Prefix) ([]netip.Prefix, string, error) {
	blocked, _, err := BlockedPrefixes(host)
	if err != nil {
		return nil, "", err
	}
	prefixes := make([]netip.Prefix, len(blocked))
	for i, text := range blocked {
		prefixes[i], err = netip.ParsePrefix(text)
		if err != nil || !prefixes[i].Addr().Is4() || prefixes[i].Bits() == 0 {
			return nil, "", errors.New("invalid effective host denial")
		}
	}
	effective := Reduce(prefixes)
	if len(effective) == 0 || len(effective) > 128 {
		return nil, "", errors.New("effective host denial exceeds bound")
	}
	canonical := make([]string, len(effective))
	for i, prefix := range effective {
		canonical[i] = prefix.String()
	}
	hash := sha256.Sum256([]byte(strings.Join(canonical, "\n")))
	return effective, hex.EncodeToString(hash[:]), nil
}
