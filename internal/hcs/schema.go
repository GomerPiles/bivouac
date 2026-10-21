// Package hcs is a typed binding to the Windows Host Compute Service
// (computecore.dll) for disposable Hyper-V guests. Documents are schema 2.1
// structures, never caller-assembled JSON text or untyped maps.
//
// Field names follow Microsoft's published schema; only the fields bivouac
// uses are modelled. Optional devices are pointers or omitted maps so that an
// absent device is absent from the document rather than present and empty.
package hcs

// Schema21 is the only schema version bivouac emits.
func Schema21() Version { return Version{Major: 2, Minor: 1} }

type Version struct {
	Major int `json:"Major"`
	Minor int `json:"Minor"`
}

// ComputeSystem is the HcsCreateComputeSystem document.
type ComputeSystem struct {
	Owner         string  `json:"Owner"`
	SchemaVersion Version `json:"SchemaVersion"`
	// TerminateOnLastHandleClosed binds the guest's lifetime to the process
	// holding its handles: if that process exits, HCS terminates the guest.
	TerminateOnLastHandleClosed bool            `json:"ShouldTerminateOnLastHandleClosed"`
	VirtualMachine              *VirtualMachine `json:"VirtualMachine"`
}

type VirtualMachine struct {
	Chipset          Chipset           `json:"Chipset"`
	ComputeTopology  Topology          `json:"ComputeTopology"`
	Devices          Devices           `json:"Devices"`
	SecuritySettings *SecuritySettings `json:"SecuritySettings,omitempty"`
	GuestState       *GuestState       `json:"GuestState,omitempty"`
}

type Chipset struct {
	Uefi *Uefi `json:"Uefi,omitempty"`
}

// SecureBootMicrosoftWindows is Hyper-V's "Microsoft Windows" Secure Boot
// template.
const SecureBootMicrosoftWindows = "1734c6e8-3154-4dda-ba5f-a874cc483422"

type Uefi struct {
	Console                 string `json:"Console,omitempty"`
	ApplySecureBootTemplate string `json:"ApplySecureBootTemplate,omitempty"`
	SecureBootTemplateID    string `json:"SecureBootTemplateId,omitempty"`
}

type Topology struct {
	Memory    Memory    `json:"Memory"`
	Processor Processor `json:"Processor"`
}

// Memory is physically backed unless AllowOvercommit makes it virtual-address
// backed. With EnableDeferredCommit, the host commits guest memory as the guest
// touches it rather than at start.
type Memory struct {
	SizeInMB             uint64 `json:"SizeInMB"`
	AllowOvercommit      bool   `json:"AllowOvercommit,omitempty"`
	EnableDeferredCommit bool   `json:"EnableDeferredCommit,omitempty"`
}

type Processor struct {
	Count uint32 `json:"Count"`
}

type Devices struct {
	Scsi            map[string]Scsi           `json:"Scsi,omitempty"`
	VideoMonitor    *VideoMonitor             `json:"VideoMonitor,omitempty"`
	Keyboard        *Keyboard                 `json:"Keyboard,omitempty"`
	Mouse           *Mouse                    `json:"Mouse,omitempty"`
	HvSocket        *HvSocket                 `json:"HvSocket,omitempty"`
	Plan9           *Plan9                    `json:"Plan9,omitempty"`
	NetworkAdapters map[string]NetworkAdapter `json:"NetworkAdapters,omitempty"`
}

// Scsi controllers are keyed by name; attachments by LUN ("0", "1", ...).
type Scsi struct {
	Attachments map[string]Attachment `json:"Attachments"`
}

const (
	AttachmentVirtualDisk = "VirtualDisk"
	AttachmentISO         = "Iso"
)

type Attachment struct {
	Type     string `json:"Type"`
	Path     string `json:"Path"`
	ReadOnly bool   `json:"ReadOnly,omitempty"`
}

type VideoMonitor struct {
	HorizontalResolution uint16 `json:"HorizontalResolution"`
	VerticalResolution   uint16 `json:"VerticalResolution"`
}

type Keyboard struct{}
type Mouse struct{}

type HvSocket struct {
	HvSocketConfig HvSocketConfig `json:"HvSocketConfig"`
}

// HvSocketConfig maps a service GUID to the host principals that may bind
// (listen for the guest) or connect (dial into the guest), as SDDL.
type HvSocketConfig struct {
	ServiceTable map[string]HvSocketService `json:"ServiceTable"`
}

type HvSocketService struct {
	BindSecurityDescriptor    string `json:"BindSecurityDescriptor"`
	ConnectSecurityDescriptor string `json:"ConnectSecurityDescriptor"`
	AllowWildcardBinds        bool   `json:"AllowWildcardBinds"`
}

type Plan9 struct {
	Shares []Plan9Share `json:"Shares"`
}

// Plan9ShareReadOnly is the share flag that denies guest writes.
const Plan9ShareReadOnly = 1

type Plan9Share struct {
	Name       string `json:"Name"`
	AccessName string `json:"AccessName"`
	Path       string `json:"Path"`
	Port       uint32 `json:"Port"`
	Flags      uint32 `json:"Flags"`
}

type NetworkAdapter struct {
	EndpointID string `json:"EndpointId"`
	MacAddress string `json:"MacAddress,omitempty"`
}

type SecuritySettings struct {
	EnableTpm bool       `json:"EnableTpm"`
	Isolation *Isolation `json:"Isolation,omitempty"`
}

type Isolation struct {
	IsolationType string `json:"IsolationType"`
}

type GuestState struct {
	GuestStateFilePath   string `json:"GuestStateFilePath"`
	RuntimeStateFilePath string `json:"RuntimeStateFilePath"`
}

// ModifyRequest is the HcsModifyComputeSystem document.
type ModifyRequest struct {
	ResourcePath string `json:"ResourcePath"`
	RequestType  string `json:"RequestType"`
	Settings     any    `json:"Settings,omitempty"`
}

// GPU is the settings document for ResourcePathGPU.
type GPU struct {
	AssignmentMode       string `json:"AssignmentMode"`
	AllowVendorExtension bool   `json:"AllowVendorExtension"`
}

const (
	ResourcePathGPU = "VirtualMachine/ComputeTopology/Gpu"
	RequestUpdate   = "Update"
	// GPUAssignDefault partitions the host's default GPU into the guest.
	GPUAssignDefault = "Default"
)

// AssignDefaultGPU requests a GPU-PV partition of the host's default GPU. It is
// applied after Start: the guest needs its running runtime identity.
func AssignDefaultGPU() ModifyRequest {
	return ModifyRequest{ResourcePath: ResourcePathGPU, RequestType: RequestUpdate, Settings: GPU{AssignmentMode: GPUAssignDefault, AllowVendorExtension: true}}
}

// Properties is the schema's default property response. Owner and RuntimeID
// together identify one native instance of a compute system name.
type Properties struct {
	ID         string `json:"Id"`
	Owner      string `json:"Owner"`
	SystemType string `json:"SystemType"`
	RuntimeID  string `json:"RuntimeId"`
	State      string `json:"State"`
}

const (
	StateRunning            = "Running"
	StateStopped            = "Stopped"
	SystemTypeVM            = "VirtualMachine"
	ExitGraceful            = "GracefulExit"
	IsolationGuestStateOnly = "GuestStateOnly"
)

// ExitStatus is the HcsWaitForComputeSystemExit result.
type ExitStatus struct {
	Status   int32  `json:"Status"`
	ExitType string `json:"ExitType"`
}

// Graceful reports a successful guest-initiated shutdown, the only exit that
// proves a disk was flushed by its guest.
func (e ExitStatus) Graceful() bool { return e.Status == 0 && e.ExitType == ExitGraceful }
