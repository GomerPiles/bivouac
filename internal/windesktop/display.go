package windesktop

// Topology contains only bounded numeric and boolean desktop observations.
// AdapterKind: 1 = Hyper-V synthetic video, 2 = AppSandboxVDD, 3 = other
// (including unresolved hardware ID); zero means no primary was observed.
type Topology struct {
	TopologyValid        bool   `json:"topology_valid"`
	ActiveDisplays       uint32 `json:"active_display_count"`
	PrimaryDisplays      uint32 `json:"primary_display_count"`
	PrimaryWidth         uint32 `json:"primary_width"`
	PrimaryHeight        uint32 `json:"primary_height"`
	VirtualEqualsPrimary bool   `json:"virtual_equals_primary"`
	AdapterKind          uint32 `json:"primary_adapter_kind"`
	VDDNodes             uint32 `json:"vdd_node_count"`
	HyperVEnabled        bool   `json:"hyperv_video_enabled"`
	HyperVStarted        bool   `json:"hyperv_video_started"`
	ProbeForeground      bool   `json:"probe_foreground"`
	ProbeOnPrimary       bool   `json:"probe_on_primary"`
	ProbeInput           bool   `json:"probe_input_received"`
	SecurityWindow       bool   `json:"security_window_found"`
	SecurityOnPrimary    bool   `json:"security_on_primary"`
}

func (t Topology) SinglePrimary() bool {
	return t.TopologyValid && t.ActiveDisplays == 1 && t.PrimaryDisplays == 1 &&
		t.PrimaryWidth > 0 && t.PrimaryWidth <= 65536 && t.PrimaryHeight > 0 && t.PrimaryHeight <= 65536 &&
		t.VirtualEqualsPrimary
}

func (t Topology) SyntheticOK() bool {
	return t.SinglePrimary() && t.AdapterKind == 1 && t.VDDNodes == 0 && t.HyperVEnabled && t.HyperVStarted
}

func (t Topology) LabOK() bool {
	return t.SyntheticOK() && t.ProbeForeground && t.ProbeOnPrimary && t.ProbeInput
}
