package appsandbox

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
