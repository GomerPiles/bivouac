//go:build windows

package hostnet

import (
	"strings"
	"testing"
)

const guest = "bivouac-windows-0a1b2c3d"

func validPlan() Plan {
	return Plan{
		NetworkID: "11111111-1111-4111-8111-111111111111", EndpointID: "22222222-2222-4222-8222-222222222222", FirewallCreator: "33333333-3333-4333-8333-333333333333",
		NetworkName: guest + "-net", EndpointName: guest + "-ep", Subnet: "10.251.0.16/28", Gateway: "10.251.0.17", Address: "10.251.0.18",
		MAC: MAC(guest), Layer: guest, Blocked: []string{"10.0.0.0/8", "192.168.0.0/16"}, HostSnapshot: strings.Repeat("a", 64),
	}
}

func TestPlansAreBoundToTheirGuestAndPool(t *testing.T) {
	if err := validPlan().Validate(guest); err != nil {
		t.Fatal(err)
	}
	if err := validPlan().Validate("bivouac-windows-ffffffff"); err == nil {
		t.Fatal("plan accepted for another guest")
	}
	for name, mutate := range map[string]func(*Plan){
		"App Sandbox pool":     func(p *Plan) { p.Subnet, p.Gateway, p.Address = "10.250.0.16/28", "10.250.0.17", "10.250.0.18" },
		"wide subnet":          func(p *Plan) { p.Subnet = "10.251.0.0/24" },
		"gateway mismatch":     func(p *Plan) { p.Gateway = "10.251.0.20" },
		"shared IDs":           func(p *Plan) { p.EndpointID = p.NetworkID },
		"foreign MAC":          func(p *Plan) { p.MAC = "02-42-0A-1B-2C-3D" },
		"foreign layer":        func(p *Plan) { p.Layer = "bivouac-other" },
		"no denials":           func(p *Plan) { p.Blocked = nil },
		"IPv6 denial":          func(p *Plan) { p.Blocked = []string{"fe80::/10"} },
		"unmasked denial":      func(p *Plan) { p.Blocked = []string{"10.1.2.3/8"} },
		"missing snapshot":     func(p *Plan) { p.HostSnapshot = "" },
		"malformed network ID": func(p *Plan) { p.NetworkID = "not-a-guid" },
	} {
		p := validPlan()
		mutate(&p)
		if err := p.Validate(guest); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if MAC(guest) == MAC("bivouac-windows-ffffffff") || !strings.HasPrefix(MAC(guest), "02-43-") {
		t.Fatal("MAC derivation", MAC(guest))
	}
}

func TestNativeStateMustMatchThePlan(t *testing.T) {
	p := validPlan()
	var network hcnNetwork
	network.ID, network.Name, network.Type = p.NetworkID, p.NetworkName, "ICS"
	network.Health.Extra.SwitchGUID = "{" + strings.ToUpper(p.NetworkID) + "}"
	network.IPAMs = []struct {
		Subnets []struct {
			IPAddressPrefix string
			Routes          []struct {
				NextHop           string
				DestinationPrefix string
			}
		}
	}{{Subnets: []struct {
		IPAddressPrefix string
		Routes          []struct {
			NextHop           string
			DestinationPrefix string
		}
	}{{IPAddressPrefix: p.Subnet, Routes: []struct {
		NextHop           string
		DestinationPrefix string
	}{{NextHop: p.Gateway, DestinationPrefix: "0.0.0.0/0"}}}}}}
	if !networkMatches(p, network) {
		t.Fatal("matching network refused")
	}
	network.Type = "NAT"
	if networkMatches(p, network) {
		t.Fatal("shared NAT network accepted")
	}

	var endpoint hcnEndpoint
	endpoint.ID, endpoint.Name, endpoint.HostComputeNetwork, endpoint.MACAddress = p.EndpointID, p.EndpointName, p.NetworkID, strings.ToLower(p.MAC)
	endpoint.IPConfigurations = []struct {
		IPAddress    string
		PrefixLength int
	}{{p.Address, 28}}
	endpoint.Policies = []struct {
		Type     string
		Settings struct {
			Name        string
			VMCreatorID string
			PolicyFlags int
		}
	}{{Type: "PortName"}, {Type: "Firewall"}}
	endpoint.Policies[1].Settings.VMCreatorID = p.FirewallCreator
	if !endpointMatches(p, endpoint) {
		t.Fatal("matching endpoint refused")
	}
	p.VMRuntimeID = "44444444-4444-4444-8444-444444444444"
	if endpointMatches(p, endpoint) {
		t.Fatal("endpoint bound to no VM accepted for a committed binding")
	}
	endpoint.Health.Extra.VirtualMachine = p.VMRuntimeID
	if !endpointMatches(p, endpoint) {
		t.Fatal("bound endpoint refused")
	}
	endpoint.Health.Extra.SharedContainers = []string{"other"}
	if endpointMatches(p, endpoint) {
		t.Fatal("shared endpoint accepted")
	}
}
