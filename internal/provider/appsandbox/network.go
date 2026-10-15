package appsandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strings"
)

// NetworkPlan is protected creation intent for one dedicated switch and port.
// Native IDs are assigned and journalled before creation, never discovered by
// a shared switch name or inferred from the host's default network.
type NetworkPlan struct {
	NetworkID       string   `json:"network_id"`
	EndpointID      string   `json:"endpoint_id"`
	FirewallCreator string   `json:"firewall_creator"`
	VMRuntimeID     string   `json:"vm_runtime_id,omitempty"`
	NetworkName     string   `json:"network_name"`
	EndpointName    string   `json:"endpoint_name"`
	Subnet          string   `json:"subnet"`
	Gateway         string   `json:"gateway"`
	Address         string   `json:"address"`
	MAC             string   `json:"mac"`
	Layer           string   `json:"layer"`
	Blocked         []string `json:"blocked"`
	HostSnapshot    string   `json:"host_snapshot"`
}

// BlockedPrefixes includes non-public ranges and every host interface's
// connected prefix (including public addresses). IPv6 is separately denied
// entirely by the initial Windows provider. The native backend refreshes this
// snapshot before admitting a runner and refuses changed policy during jobs.
func BlockedPrefixes(host []netip.Prefix) ([]string, string, error) {
	result := strings.Fields("0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4")
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
