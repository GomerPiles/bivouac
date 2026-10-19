//go:build windows

package appsandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/GomerPiles/bivouac/internal/command"
	"github.com/GomerPiles/bivouac/internal/netpolicy"
	"github.com/GomerPiles/bivouac/internal/provider"
	"golang.org/x/sys/windows"
)

type windowsNetwork struct {
	api     *hcnAPI
	vfp     VFP
	records *Records
}

func newWindowsNetwork(records *Records) (*windowsNetwork, error) {
	api := newHCN()
	if err := api.check(); err != nil {
		return nil, err
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	binary := filepath.Join(system, "vfpctrl.exe")
	if _, err = os.Stat(binary); err != nil {
		return nil, errors.New("system VFP tool unavailable")
	}
	return &windowsNetwork{api: api, vfp: VFP{Binary: binary, Commands: command.Native{}}, records: records}, nil
}

type hcnNetwork struct {
	ID     string
	Name   string
	Type   string
	Health struct{ Extra struct{ SwitchGUID string } }
	IPAMs  []struct {
		Subnets []struct {
			IPAddressPrefix string
			Routes          []struct {
				NextHop           string
				DestinationPrefix string
			}
		}
	}
}
type hcnEndpoint struct {
	ID                 string
	Name               string
	HostComputeNetwork string
	MACAddress         string
	IPConfigurations   []struct {
		IPAddress    string
		PrefixLength int
	}
	Policies []struct {
		Type     string
		Settings struct {
			Name        string
			VMCreatorID string
			PolicyFlags int
		}
	}
	Health struct {
		Extra struct {
			VirtualMachine   string
			SharedContainers []string
		}
	}
}
type vfpPortInventory struct {
	Ports []struct {
		Name               string
		SwitchName         string
		SwitchFriendlyName string
		IsPortConnected    bool
		VMID               string
	}
	VfpCtrlTrailer     *struct{ NumErrors int }
	VfpCtrlErrorRecord struct {
		ErrorCode int
		Function  string
	}
}

func newNativeGUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
func sameNativeGUID(a, b string) bool {
	return strings.EqualFold(strings.Trim(a, "{}"), strings.Trim(b, "{}"))
}
func validateNetworkPlan(r EngineRecord) error {
	n := r.Network
	if n == nil {
		return errors.New("network intent missing")
	}
	for _, id := range []string{n.NetworkID, n.EndpointID, n.FirewallCreator} {
		if len(id) != 36 {
			return errors.New("invalid native network ID")
		}
		if _, err := windows.GUIDFromString("{" + id + "}"); err != nil {
			return err
		}
	}
	if n.NetworkID == n.EndpointID || n.EndpointID == n.FirewallCreator || n.NetworkID == n.FirewallCreator {
		return errors.New("native network IDs overlap")
	}
	if n.NetworkName != r.Clone.NativeName+"-net" || n.EndpointName != r.Clone.NativeName+"-ep" || n.Layer != "bivouac-"+r.Clone.Meta.ControllerID+"-"+r.Clone.Meta.InstanceID {
		return provider.ErrNotOwned
	}
	subnet, err := netip.ParsePrefix(n.Subnet)
	if err != nil || !subnet.Addr().Is4() || subnet.Bits() != 28 || subnet != subnet.Masked() || !netip.MustParsePrefix("10.250.0.0/16").Contains(subnet.Addr()) {
		return errors.New("invalid dedicated subnet")
	}
	if subnet.Addr().Next().String() != n.Gateway || subnet.Addr().Next().Next().String() != n.Address || len(n.Blocked) == 0 || len(n.Blocked) > 128 || len(n.HostSnapshot) != 64 {
		return errors.New("invalid network policy intent")
	}
	bytes, err := hex.DecodeString(r.Clone.Meta.InstanceID)
	if err != nil {
		return err
	}
	expectedMAC := fmt.Sprintf("02-42-%02X-%02X-%02X-%02X", bytes[0], bytes[1], bytes[2], bytes[3])
	if n.MAC != expectedMAC {
		return provider.ErrNotOwned
	}
	for _, prefix := range n.Blocked {
		p, err := netip.ParsePrefix(prefix)
		if err != nil || !p.Addr().Is4() || p != p.Masked() {
			return errors.New("invalid IPv4 denial prefix")
		}
	}
	return nil
}
func (w *windowsNetwork) hostPrefixes(all []EngineRecord) ([]netip.Prefix, error) {
	excluded := map[string]bool{}
	for _, r := range all {
		excluded["vEthernet ("+r.Clone.NativeName+"-net)"] = true
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []netip.Prefix
	for _, adapter := range interfaces {
		if excluded[adapter.Name] {
			continue
		}
		addresses, err := adapter.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return nil, errors.New("invalid host interface address")
			}
			result = append(result, prefix)
		}
	}
	return result, nil
}
func (w *windowsNetwork) Plan(ctx context.Context, r CloneRecord, all []EngineRecord) (NetworkPlan, error) {
	if err := ctx.Err(); err != nil {
		return NetworkPlan{}, err
	}
	prefixes, err := w.hostPrefixes(all)
	if err != nil {
		return NetworkPlan{}, err
	}
	blocked, snapshot, err := netpolicy.BlockedPrefixes(prefixes)
	if err != nil {
		return NetworkPlan{}, err
	}
	if len(blocked) > 128 {
		return NetworkPlan{}, errors.New("host policy exceeds supported bound")
	}
	occupied := append([]netip.Prefix(nil), prefixes...)
	for _, record := range all {
		if record.Network != nil {
			prefix, err := netip.ParsePrefix(record.Network.Subnet)
			if err != nil {
				return NetworkPlan{}, err
			}
			occupied = append(occupied, prefix)
		}
	}
	ids, err := w.api.enumerateNetworks()
	if err != nil {
		return NetworkPlan{}, err
	}
	for _, id := range ids {
		handle, err := w.api.open("Network", strings.Trim(id, "{}"))
		if err != nil {
			return NetworkPlan{}, err
		}
		var network hcnNetwork
		err = w.api.query("Network", handle, &network)
		w.api.close("Network", handle)
		if err != nil {
			return NetworkPlan{}, err
		}
		for _, ipam := range network.IPAMs {
			for _, subnet := range ipam.Subnets {
				p, err := netip.ParsePrefix(subnet.IPAddressPrefix)
				if err != nil {
					return NetworkPlan{}, errors.New("invalid native subnet inventory")
				}
				occupied = append(occupied, p)
			}
		}
	}
	var subnet netip.Prefix
	pool := netip.MustParsePrefix("10.250.0.0/16")
	for address := pool.Addr(); pool.Contains(address); {
		candidate := netip.PrefixFrom(address, 28)
		available := true
		for _, used := range occupied {
			if candidate.Overlaps(used) {
				available = false
				break
			}
		}
		if available {
			subnet = candidate
			break
		}
		for range 16 {
			address = address.Next()
		}
	}
	if !subnet.IsValid() {
		return NetworkPlan{}, errors.New("no unused isolated subnet available")
	}
	netID, err := newNativeGUID()
	if err != nil {
		return NetworkPlan{}, err
	}
	epID, err := newNativeGUID()
	if err != nil {
		return NetworkPlan{}, err
	}
	creator, err := newNativeGUID()
	if err != nil {
		return NetworkPlan{}, err
	}
	bytes, err := hex.DecodeString(r.Meta.InstanceID)
	if err != nil {
		return NetworkPlan{}, err
	}
	n := NetworkPlan{NetworkID: netID, EndpointID: epID, FirewallCreator: creator, NetworkName: r.NativeName + "-net", EndpointName: r.NativeName + "-ep", Subnet: subnet.String(), Gateway: subnet.Addr().Next().String(), Address: subnet.Addr().Next().Next().String(), MAC: fmt.Sprintf("02-42-%02X-%02X-%02X-%02X", bytes[0], bytes[1], bytes[2], bytes[3]), Layer: "bivouac-" + r.Meta.ControllerID + "-" + r.Meta.InstanceID, Blocked: blocked, HostSnapshot: snapshot}
	return n, validateNetworkPlan(EngineRecord{Clone: r, Network: &n})
}
func networkMatches(n NetworkPlan, actual hcnNetwork) bool {
	if !sameNativeGUID(actual.ID, n.NetworkID) || actual.Name != n.NetworkName || actual.Type != "ICS" || !sameNativeGUID(actual.Health.Extra.SwitchGUID, n.NetworkID) || len(actual.IPAMs) != 1 || len(actual.IPAMs[0].Subnets) != 1 {
		return false
	}
	subnet := actual.IPAMs[0].Subnets[0]
	return subnet.IPAddressPrefix == n.Subnet && len(subnet.Routes) == 1 && subnet.Routes[0].NextHop == n.Gateway && subnet.Routes[0].DestinationPrefix == "0.0.0.0/0"
}
func endpointMatches(n NetworkPlan, actual hcnEndpoint) bool {
	if !sameNativeGUID(actual.ID, n.EndpointID) || actual.Name != n.EndpointName || !sameNativeGUID(actual.HostComputeNetwork, n.NetworkID) || !strings.EqualFold(actual.MACAddress, n.MAC) || len(actual.IPConfigurations) != 1 || actual.IPConfigurations[0].IPAddress != n.Address || actual.IPConfigurations[0].PrefixLength != 28 || len(actual.Health.Extra.SharedContainers) != 0 {
		return false
	}
	creators := 0
	for _, policy := range actual.Policies {
		switch policy.Type {
		case "Firewall":
			if !sameNativeGUID(policy.Settings.VMCreatorID, n.FirewallCreator) || policy.Settings.PolicyFlags != 0 {
				return false
			}
			creators++
		case "PortName":
			if policy.Settings.Name != "" {
				return false
			}
		default:
			return false
		}
	}
	return creators == 1 && (n.VMRuntimeID == "" || sameNativeGUID(actual.Health.Extra.VirtualMachine, n.VMRuntimeID))
}
func (w *windowsNetwork) properties(r EngineRecord) error {
	var network hcnNetwork
	var endpoint hcnEndpoint
	if err := validateNetworkPlan(r); err != nil {
		return err
	}
	handle, err := w.api.open("Network", r.Network.NetworkID)
	if err != nil {
		return err
	}
	err = w.api.query("Network", handle, &network)
	w.api.close("Network", handle)
	if err != nil {
		return err
	}
	if !networkMatches(*r.Network, network) {
		return provider.ErrNotOwned
	}
	handle, err = w.api.open("Endpoint", r.Network.EndpointID)
	if err != nil {
		return err
	}
	err = w.api.query("Endpoint", handle, &endpoint)
	w.api.close("Endpoint", handle)
	if err != nil {
		return err
	}
	if !endpointMatches(*r.Network, endpoint) {
		return provider.ErrNotOwned
	}
	return nil
}
func (w *windowsNetwork) port(ctx context.Context, n NetworkPlan, required bool) (bool, error) {
	data, err := w.vfp.Commands.Output(ctx, w.vfp.Binary, []string{"/list-vmswitch-port", "/format", "1"})
	if err != nil {
		return false, err
	}
	var ports vfpPortInventory
	if len(data) > maxResponseBytes || json.Unmarshal(data, &ports) != nil || ports.VfpCtrlTrailer == nil {
		return false, errors.New("invalid native switch port inventory")
	}
	emptyEnumeration := ports.VfpCtrlTrailer.NumErrors == 1 && ports.VfpCtrlErrorRecord.ErrorCode == 259 && ports.VfpCtrlErrorRecord.Function == "JsonWriteItemListStart" && len(ports.Ports) == 0
	if ports.VfpCtrlTrailer.NumErrors != 0 && !emptyEnumeration {
		return false, errors.New("native switch port enumeration failed")
	}
	count := 0
	connected := false
	for _, port := range ports.Ports {
		if sameNativeGUID(port.Name, n.EndpointID) {
			count++
			if !sameNativeGUID(port.SwitchName, n.NetworkID) || port.SwitchFriendlyName != n.NetworkName || (port.VMID != "" && n.VMRuntimeID != "" && !sameNativeGUID(port.VMID, n.VMRuntimeID)) {
				return false, provider.ErrNotOwned
			}
			connected = port.IsPortConnected
		}
	}
	if count > 1 || (required && count != 1) {
		return false, errors.New("owned native switch port missing or ambiguous")
	}
	return connected, nil
}
func (w *windowsNetwork) Attach(ctx context.Context, r EngineRecord) error {
	if err := validateNetworkPlan(r); err != nil {
		return err
	}
	n := r.Network
	for _, kind := range []string{"Network", "Endpoint"} {
		id := n.NetworkID
		code := uint32(0x803b0001)
		if kind == "Endpoint" {
			id = n.EndpointID
			code = 0x803b0002
		}
		handle, err := w.api.open(kind, id)
		w.api.close(kind, handle)
		if !nativeMissing(err, code) {
			return errors.New("native network intent already exists or absence unconfirmed")
		}
	}
	settings := map[string]any{"Name": n.NetworkName, "Type": "ICS", "IsolateSwitch": true, "Flags": 256, "Subnets": []any{map[string]any{"AddressPrefix": n.Subnet, "GatewayAddress": n.Gateway, "IpSubnets": []any{map[string]string{"IpAddressPrefix": n.Subnet}}}}}
	handle, err := w.api.create("Network", 0, n.NetworkID, settings)
	if handle != 0 {
		defer w.api.close("Network", handle)
	}
	if err != nil {
		return err
	}
	var network hcnNetwork
	if err = w.api.query("Network", handle, &network); err != nil {
		return err
	}
	if !networkMatches(*n, network) {
		return provider.ErrNotOwned
	}
	epSettings := map[string]any{"SchemaVersion": map[string]int{"Major": 2, "Minor": 16}, "Name": n.EndpointName, "HostComputeNetwork": n.NetworkID, "MacAddress": n.MAC, "IpConfigurations": []any{map[string]any{"IpAddress": n.Address, "PrefixLength": 28}}, "Routes": []any{map[string]string{"NextHop": n.Gateway, "DestinationPrefix": "0.0.0.0/0"}}, "Dns": map[string]any{"ServerList": []string{"1.1.1.1", "8.8.8.8"}}, "Policies": []any{map[string]any{"Type": "PortName", "Settings": map[string]string{"Name": ""}}, map[string]any{"Type": "Firewall", "Settings": map[string]any{"VmCreatorId": n.FirewallCreator, "PolicyFlags": 0}}}}
	ep, err := w.api.create("Endpoint", handle, n.EndpointID, epSettings)
	if ep != 0 {
		defer w.api.close("Endpoint", ep)
	}
	if err != nil {
		return err
	}
	var endpoint hcnEndpoint
	if err = w.api.query("Endpoint", ep, &endpoint); err != nil {
		return err
	}
	if !endpointMatches(*n, endpoint) {
		return provider.ErrNotOwned
	}
	if err = w.api.attach(ctx, r.Clone.NativeName, *n); err != nil {
		return err
	}
	if err = w.api.query("Endpoint", ep, &endpoint); err != nil {
		return err
	}
	if !endpointMatches(*n, endpoint) || endpoint.Health.Extra.VirtualMachine == "" {
		return provider.ErrNotOwned
	}
	n.VMRuntimeID = endpoint.Health.Extra.VirtualMachine
	if connected, err := w.port(ctx, *n, true); err != nil {
		return err
	} else if !connected {
		return errors.New("owned native port not connected")
	}
	if err = w.vfp.Block(ctx, *n); err != nil {
		return err
	}
	if err = w.vfp.Add(ctx, *n); err != nil {
		return err
	}
	return w.vfp.Unblock(ctx, *n)
}
func (w *windowsNetwork) Verify(ctx context.Context, r EngineRecord) error {
	if err := w.properties(r); err != nil {
		return err
	}
	if r.Network.VMRuntimeID == "" {
		return errors.New("owned VM binding not committed")
	}
	if connected, err := w.port(ctx, *r.Network, true); err != nil {
		return err
	} else if !connected {
		return errors.New("owned switch port disconnected")
	}
	all, err := w.records.All()
	if err != nil {
		return err
	}
	prefixes, err := w.hostPrefixes(all)
	if err != nil {
		return err
	}
	blocked, snapshot, err := netpolicy.BlockedPrefixes(prefixes)
	if err != nil {
		return err
	}
	if snapshot != r.Network.HostSnapshot || !slices.Equal(blocked, r.Network.Blocked) {
		return errors.New("host interface policy changed; discard guest")
	}
	if err = w.vfp.Verify(ctx, *r.Network); err != nil {
		return err
	}
	return w.vfp.Ready(ctx, *r.Network)
}
func (w *windowsNetwork) Block(ctx context.Context, r EngineRecord) error {
	if r.Network == nil {
		return nil
	}
	err := w.properties(r)
	if nativeMissing(err, 0x803b0001) || nativeMissing(err, 0x803b0002) {
		return nil
	}
	if err != nil {
		return err
	}
	if connected, err := w.port(ctx, *r.Network, false); err != nil {
		return err
	} else if !connected {
		return nil
	}
	return w.vfp.Block(ctx, *r.Network)
}
func (w *windowsNetwork) Delete(ctx context.Context, r EngineRecord) error {
	if err := validateNetworkPlan(r); err != nil {
		return err
	}
	n := r.Network
	netHandle, err := w.api.open("Network", n.NetworkID)
	if netHandle != 0 {
		defer w.api.close("Network", netHandle)
	}
	if err != nil && !nativeMissing(err, 0x803b0001) {
		return err
	}
	if err == nil {
		var network hcnNetwork
		if err = w.api.query("Network", netHandle, &network); err != nil {
			return err
		}
		if !networkMatches(*n, network) {
			return provider.ErrNotOwned
		}
	}
	epHandle, epErr := w.api.open("Endpoint", n.EndpointID)
	if epHandle != 0 {
		defer w.api.close("Endpoint", epHandle)
	}
	if epErr != nil && !nativeMissing(epErr, 0x803b0002) {
		return epErr
	}
	if epErr == nil {
		var endpoint hcnEndpoint
		if err = w.api.query("Endpoint", epHandle, &endpoint); err != nil {
			return err
		}
		if !endpointMatches(*n, endpoint) {
			return provider.ErrNotOwned
		}
		if connected, err := w.port(ctx, *n, false); err != nil {
			return err
		} else if connected {
			return errors.New("owned endpoint still attached; retain cleanup")
		}
		if err = w.api.delete("Endpoint", n.EndpointID); err != nil {
			return err
		}
	}
	if netHandle != 0 {
		if err = w.api.delete("Network", n.NetworkID); err != nil {
			return err
		}
	}
	for _, kind := range []string{"Network", "Endpoint"} {
		id := n.NetworkID
		code := uint32(0x803b0001)
		if kind == "Endpoint" {
			id = n.EndpointID
			code = 0x803b0002
		}
		handle, err := w.api.open(kind, id)
		w.api.close(kind, handle)
		if !nativeMissing(err, code) {
			return errors.New("native network deletion unconfirmed")
		}
	}
	return nil
}
