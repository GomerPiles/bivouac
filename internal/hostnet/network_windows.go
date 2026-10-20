//go:build windows

// Package hostnet gives each disposable guest its own isolated Windows
// network: a dedicated ICS switch and endpoint, plus an owned stateless VFP
// layer on the guest's port that denies host, gateway, LAN and reserved IPv4
// and all IPv6, while public DNS and HTTPS work. It is the VM host's network
// half; it never touches a network it did not create and record.
package hostnet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"golang.org/x/sys/windows"
)

const maxNativeResponse = 1 << 20

// subnetPool is reserved for the VM host. App Sandbox's broker uses 10.250.0.0/16.
func subnetPool() netip.Prefix { return netip.MustParsePrefix("10.251.0.0/16") }

// ErrForeign reports native network state that does not match its plan.
var ErrForeign = errors.New("native network does not match its recorded plan; retained")

// Plan is one guest's network intent. It is journalled before creation, and
// every later operation proves native state against it.
type Plan struct {
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

// MAC derives a locally administered address from the guest name.
func MAC(guest string) string {
	h := sha256.Sum256([]byte(guest))
	return fmt.Sprintf("02-43-%02X-%02X-%02X-%02X", h[0], h[1], h[2], h[3])
}

// Validate checks a plan's shape and its binding to guest.
func (p Plan) Validate(guest string) error {
	for _, id := range []string{p.NetworkID, p.EndpointID, p.FirewallCreator} {
		if len(id) != 36 {
			return errors.New("invalid native network ID")
		}
		if _, err := windows.GUIDFromString("{" + id + "}"); err != nil {
			return err
		}
	}
	if p.NetworkID == p.EndpointID || p.EndpointID == p.FirewallCreator || p.NetworkID == p.FirewallCreator {
		return errors.New("native network IDs overlap")
	}
	if p.NetworkName != guest+"-net" || p.EndpointName != guest+"-ep" || p.Layer != guest || p.MAC != MAC(guest) {
		return ErrForeign
	}
	subnet, err := netip.ParsePrefix(p.Subnet)
	if err != nil || !subnet.Addr().Is4() || subnet.Bits() != 28 || subnet != subnet.Masked() || !subnetPool().Contains(subnet.Addr()) {
		return errors.New("invalid dedicated subnet")
	}
	if subnet.Addr().Next().String() != p.Gateway || subnet.Addr().Next().Next().String() != p.Address || len(p.Blocked) == 0 || len(p.Blocked) > 128 || len(p.HostSnapshot) != 64 {
		return errors.New("invalid network policy intent")
	}
	for _, prefix := range p.Blocked {
		q, err := netip.ParsePrefix(prefix)
		if err != nil || !q.Addr().Is4() || q != q.Masked() {
			return errors.New("invalid IPv4 denial prefix")
		}
	}
	return nil
}

// Manager owns the native calls. It holds no per-guest state.
type Manager struct {
	api *hcnAPI
	vfp VFP
}

func Open() (*Manager, error) {
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
	return &Manager{api: api, vfp: VFP{Binary: binary, Commands: command.Native{}}}, nil
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

func newGUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

func sameGUID(a, b string) bool {
	return strings.EqualFold(strings.Trim(a, "{}"), strings.Trim(b, "{}"))
}

// HostDenial is the current effective IPv4 denial and its snapshot. It is
// computed from every host interface, including other guests' switches; those
// private prefixes are already denied and do not change it.
func HostDenial() ([]string, string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, "", err
	}
	var all []netip.Prefix
	for _, adapter := range interfaces {
		addresses, err := adapter.Addrs()
		if err != nil {
			return nil, "", err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return nil, "", errors.New("invalid host interface address")
			}
			all = append(all, prefix)
		}
	}
	effective, snapshot, err := netpolicy.EffectiveDenial(all)
	if err != nil {
		return nil, "", err
	}
	blocked := make([]string, len(effective))
	for i, p := range effective {
		blocked[i] = p.String()
	}
	slices.Sort(blocked)
	return blocked, snapshot, nil
}

// Plan chooses an unused /28 and fresh native IDs for guest.
func (m *Manager) Plan(ctx context.Context, guest string, retained []Plan) (Plan, error) {
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	blocked, snapshot, err := HostDenial()
	if err != nil {
		return Plan{}, err
	}
	var occupied []netip.Prefix
	for _, r := range retained {
		prefix, err := netip.ParsePrefix(r.Subnet)
		if err != nil {
			return Plan{}, err
		}
		occupied = append(occupied, prefix)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return Plan{}, err
	}
	for _, adapter := range interfaces {
		addresses, err := adapter.Addrs()
		if err != nil {
			return Plan{}, err
		}
		for _, address := range addresses {
			if prefix, err := netip.ParsePrefix(address.String()); err == nil {
				occupied = append(occupied, prefix.Masked())
			}
		}
	}
	ids, err := m.api.enumerateNetworks()
	if err != nil {
		return Plan{}, err
	}
	for _, id := range ids {
		handle, err := m.api.open("Network", strings.Trim(id, "{}"))
		if err != nil {
			return Plan{}, err
		}
		var network hcnNetwork
		err = m.api.query("Network", handle, &network)
		m.api.close("Network", handle)
		if err != nil {
			return Plan{}, err
		}
		for _, ipam := range network.IPAMs {
			for _, subnet := range ipam.Subnets {
				p, err := netip.ParsePrefix(subnet.IPAddressPrefix)
				if err != nil {
					return Plan{}, errors.New("invalid native subnet inventory")
				}
				occupied = append(occupied, p)
			}
		}
	}
	var subnet netip.Prefix
	pool := subnetPool()
	for address := pool.Addr(); pool.Contains(address); {
		candidate := netip.PrefixFrom(address, 28)
		if !slices.ContainsFunc(occupied, candidate.Overlaps) {
			subnet = candidate
			break
		}
		for range 16 {
			address = address.Next()
		}
	}
	if !subnet.IsValid() {
		return Plan{}, errors.New("no unused isolated subnet available")
	}
	netID, err := newGUID()
	if err != nil {
		return Plan{}, err
	}
	epID, err := newGUID()
	if err != nil {
		return Plan{}, err
	}
	creator, err := newGUID()
	if err != nil {
		return Plan{}, err
	}
	p := Plan{NetworkID: netID, EndpointID: epID, FirewallCreator: creator, NetworkName: guest + "-net", EndpointName: guest + "-ep",
		Subnet: subnet.String(), Gateway: subnet.Addr().Next().String(), Address: subnet.Addr().Next().Next().String(),
		MAC: MAC(guest), Layer: guest, Blocked: blocked, HostSnapshot: snapshot}
	return p, p.Validate(guest)
}

func networkMatches(p Plan, actual hcnNetwork) bool {
	if !sameGUID(actual.ID, p.NetworkID) || actual.Name != p.NetworkName || actual.Type != "ICS" || !sameGUID(actual.Health.Extra.SwitchGUID, p.NetworkID) || len(actual.IPAMs) != 1 || len(actual.IPAMs[0].Subnets) != 1 {
		return false
	}
	subnet := actual.IPAMs[0].Subnets[0]
	return subnet.IPAddressPrefix == p.Subnet && len(subnet.Routes) == 1 && subnet.Routes[0].NextHop == p.Gateway && subnet.Routes[0].DestinationPrefix == "0.0.0.0/0"
}

func endpointMatches(p Plan, actual hcnEndpoint) bool {
	if !sameGUID(actual.ID, p.EndpointID) || actual.Name != p.EndpointName || !sameGUID(actual.HostComputeNetwork, p.NetworkID) || !strings.EqualFold(actual.MACAddress, p.MAC) || len(actual.IPConfigurations) != 1 || actual.IPConfigurations[0].IPAddress != p.Address || actual.IPConfigurations[0].PrefixLength != 28 || len(actual.Health.Extra.SharedContainers) != 0 {
		return false
	}
	creators := 0
	for _, policy := range actual.Policies {
		switch policy.Type {
		case "Firewall":
			if !sameGUID(policy.Settings.VMCreatorID, p.FirewallCreator) || policy.Settings.PolicyFlags != 0 {
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
	return creators == 1 && (p.VMRuntimeID == "" || sameGUID(actual.Health.Extra.VirtualMachine, p.VMRuntimeID))
}

const (
	networkMissing  = 0x803b0001
	endpointMissing = 0x803b0002
)

func (m *Manager) absent(kind, id string, code uint32) bool {
	handle, err := m.api.open(kind, id)
	m.api.close(kind, handle)
	return nativeMissing(err, code)
}

// Create makes the planned network and endpoint and proves both. The guest's
// creation document then names the endpoint, so its adapter exists from boot.
func (m *Manager) Create(ctx context.Context, p Plan, guest string) error {
	if err := p.Validate(guest); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !m.absent("Network", p.NetworkID, networkMissing) || !m.absent("Endpoint", p.EndpointID, endpointMissing) {
		return errors.New("native network intent already exists or absence unconfirmed")
	}
	settings := map[string]any{"Name": p.NetworkName, "Type": "ICS", "IsolateSwitch": true, "Flags": 256, "Subnets": []any{map[string]any{"AddressPrefix": p.Subnet, "GatewayAddress": p.Gateway, "IpSubnets": []any{map[string]string{"IpAddressPrefix": p.Subnet}}}}}
	handle, err := m.api.create("Network", 0, p.NetworkID, settings)
	if handle != 0 {
		defer m.api.close("Network", handle)
	}
	if err != nil {
		return err
	}
	var network hcnNetwork
	if err = m.api.query("Network", handle, &network); err != nil {
		return err
	}
	if !networkMatches(p, network) {
		return ErrForeign
	}
	epSettings := map[string]any{"SchemaVersion": map[string]int{"Major": 2, "Minor": 16}, "Name": p.EndpointName, "HostComputeNetwork": p.NetworkID, "MacAddress": p.MAC, "IpConfigurations": []any{map[string]any{"IpAddress": p.Address, "PrefixLength": 28}}, "Routes": []any{map[string]string{"NextHop": p.Gateway, "DestinationPrefix": "0.0.0.0/0"}}, "Dns": map[string]any{"ServerList": []string{"1.1.1.1", "8.8.8.8"}}, "Policies": []any{map[string]any{"Type": "PortName", "Settings": map[string]string{"Name": ""}}, map[string]any{"Type": "Firewall", "Settings": map[string]any{"VmCreatorId": p.FirewallCreator, "PolicyFlags": 0}}}}
	ep, err := m.api.create("Endpoint", handle, p.EndpointID, epSettings)
	if ep != 0 {
		defer m.api.close("Endpoint", ep)
	}
	if err != nil {
		return err
	}
	var endpoint hcnEndpoint
	if err = m.api.query("Endpoint", ep, &endpoint); err != nil {
		return err
	}
	if !endpointMatches(p, endpoint) {
		return ErrForeign
	}
	return nil
}

func (m *Manager) endpoint(p Plan) (hcnEndpoint, error) {
	var endpoint hcnEndpoint
	handle, err := m.api.open("Endpoint", p.EndpointID)
	if err != nil {
		return endpoint, err
	}
	err = m.api.query("Endpoint", handle, &endpoint)
	m.api.close("Endpoint", handle)
	return endpoint, err
}

// Port reports whether the guest's switch port exists and is connected. A
// port that exists names this plan's switch, or the plan is foreign.
func (m *Manager) Port(ctx context.Context, p Plan) (exists, connected bool, err error) {
	data, err := m.vfp.Commands.Output(ctx, m.vfp.Binary, []string{"/list-vmswitch-port", "/format", "1"})
	if err != nil {
		return false, false, err
	}
	var ports vfpPortInventory
	if len(data) > maxNativeResponse || json.Unmarshal(data, &ports) != nil || ports.VfpCtrlTrailer == nil {
		return false, false, errors.New("invalid native switch port inventory")
	}
	emptyEnumeration := ports.VfpCtrlTrailer.NumErrors == 1 && ports.VfpCtrlErrorRecord.ErrorCode == 259 && ports.VfpCtrlErrorRecord.Function == "JsonWriteItemListStart" && len(ports.Ports) == 0
	if ports.VfpCtrlTrailer.NumErrors != 0 && !emptyEnumeration {
		return false, false, errors.New("native switch port enumeration failed")
	}
	count := 0
	for _, port := range ports.Ports {
		if sameGUID(port.Name, p.EndpointID) {
			count++
			if !sameGUID(port.SwitchName, p.NetworkID) || port.SwitchFriendlyName != p.NetworkName || (port.VMID != "" && p.VMRuntimeID != "" && !sameGUID(port.VMID, p.VMRuntimeID)) {
				return false, false, ErrForeign
			}
			connected = port.IsPortConnected
		}
	}
	if count > 1 {
		return false, false, errors.New("owned native switch port ambiguous")
	}
	return count == 1, connected, nil
}

// Protect binds the endpoint to the guest's runtime and installs the owned
// VFP layer on its port: block the port, add every denial, verify them, then
// unblock. It returns the plan with its committed runtime binding.
func (m *Manager) Protect(ctx context.Context, p Plan, guest, runtimeID string) (Plan, error) {
	if err := p.Validate(guest); err != nil {
		return p, err
	}
	endpoint, err := m.endpoint(p)
	if err != nil {
		return p, err
	}
	if !endpointMatches(p, endpoint) || endpoint.Health.Extra.VirtualMachine == "" || (runtimeID != "" && !sameGUID(endpoint.Health.Extra.VirtualMachine, runtimeID)) {
		return p, ErrForeign
	}
	p.VMRuntimeID = endpoint.Health.Extra.VirtualMachine
	exists, connected, err := m.Port(ctx, p)
	if err != nil {
		return p, err
	}
	if !exists || !connected {
		return p, errors.New("owned native switch port missing or disconnected")
	}
	if err = m.vfp.Block(ctx, p); err != nil {
		return p, err
	}
	if err = m.vfp.Add(ctx, p); err != nil {
		return p, err
	}
	return p, m.vfp.Unblock(ctx, p)
}

// Verify reproves the network, endpoint, runtime binding, port, VFP rules and
// that the host's effective denial has not changed since the plan.
func (m *Manager) Verify(ctx context.Context, p Plan, guest string) error {
	if err := p.Validate(guest); err != nil {
		return err
	}
	if p.VMRuntimeID == "" {
		return errors.New("owned VM binding not committed")
	}
	var network hcnNetwork
	handle, err := m.api.open("Network", p.NetworkID)
	if err != nil {
		return err
	}
	err = m.api.query("Network", handle, &network)
	m.api.close("Network", handle)
	if err != nil {
		return err
	}
	if !networkMatches(p, network) {
		return ErrForeign
	}
	endpoint, err := m.endpoint(p)
	if err != nil {
		return err
	}
	if !endpointMatches(p, endpoint) {
		return ErrForeign
	}
	if exists, connected, err := m.Port(ctx, p); err != nil {
		return err
	} else if !exists || !connected {
		return errors.New("owned switch port disconnected")
	}
	blocked, snapshot, err := HostDenial()
	if err != nil {
		return err
	}
	if snapshot != p.HostSnapshot || !slices.Equal(blocked, p.Blocked) {
		return errors.New("host interface policy changed; discard guest")
	}
	if err = m.vfp.Verify(ctx, p); err != nil {
		return err
	}
	return m.vfp.Ready(ctx, p)
}

// Block blocks the guest's port if it still exists.
func (m *Manager) Block(ctx context.Context, p Plan) error {
	exists, connected, err := m.Port(ctx, p)
	if err != nil || !exists || !connected {
		return err
	}
	return m.vfp.Block(ctx, p)
}

// Delete removes the endpoint and network only after the guest's port is
// disconnected and both match the plan, then confirms native absence.
func (m *Manager) Delete(ctx context.Context, p Plan, guest string) error {
	if err := p.Validate(guest); err != nil {
		return err
	}
	netHandle, err := m.api.open("Network", p.NetworkID)
	if netHandle != 0 {
		defer m.api.close("Network", netHandle)
	}
	if err != nil && !nativeMissing(err, networkMissing) {
		return err
	}
	if err == nil {
		var network hcnNetwork
		if err = m.api.query("Network", netHandle, &network); err != nil {
			return err
		}
		if !networkMatches(p, network) {
			return ErrForeign
		}
	}
	epHandle, epErr := m.api.open("Endpoint", p.EndpointID)
	if epHandle != 0 {
		defer m.api.close("Endpoint", epHandle)
	}
	if epErr != nil && !nativeMissing(epErr, endpointMissing) {
		return epErr
	}
	if epErr == nil {
		var endpoint hcnEndpoint
		if err = m.api.query("Endpoint", epHandle, &endpoint); err != nil {
			return err
		}
		probe := p
		probe.VMRuntimeID = ""
		if !endpointMatches(probe, endpoint) {
			return ErrForeign
		}
		// A stopped guest's port can remain, disconnected, until its endpoint
		// is deleted; only a connected port means the endpoint is in use.
		if _, connected, err := m.Port(ctx, p); err != nil {
			return err
		} else if connected {
			return errors.New("owned endpoint still attached; retain cleanup")
		}
		if err = m.api.delete("Endpoint", p.EndpointID); err != nil {
			return err
		}
	}
	if netHandle != 0 {
		if err = m.api.delete("Network", p.NetworkID); err != nil {
			return err
		}
	}
	if !m.absent("Network", p.NetworkID, networkMissing) || !m.absent("Endpoint", p.EndpointID, endpointMissing) {
		return errors.New("native network deletion unconfirmed")
	}
	return nil
}
