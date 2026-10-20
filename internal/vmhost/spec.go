//go:build windows

// Package vmhost is the privileged half of the Windows HCS provider. It owns
// compute systems, their per-job differencing disks and a journal proving
// which guests it created. It never holds GitHub credentials, job data or guest
// output; the unprivileged manager handles everything a guest can influence.
//
// Every guest is created with ShouldTerminateOnLastHandleClosed and its handle
// stays with the Host, so guests end when the VM host process does.
package vmhost

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/GomerPiles/bivouac/internal/hcs"
	"github.com/GomerPiles/bivouac/internal/hostnet"
)

// NamePrefix marks compute systems and journal entries bivouac created.
const NamePrefix = "bivouac-"

// Spec is one guest's creation intent. It is journalled before any native
// mutation and is the only input from which its HCS document is built.
type Spec struct {
	Name     string `json:"name"`
	Image    string `json:"image"`
	CPU      uint32 `json:"cpu"`
	MemoryMB uint64 `json:"memory_mb"`
	// LazyMemory backs guest RAM with host virtual memory committed on use.
	LazyMemory bool `json:"lazy_memory,omitempty"`
	GPU        bool `json:"gpu"`
	// Network attaches an isolated endpoint with the hostnet policy.
	Network  bool      `json:"network,omitempty"`
	Services []Service `json:"services,omitempty"`
	// Labels are the creator's own bounded ownership metadata, such as its
	// controller and instance IDs. They grant nothing.
	Labels map[string]string `json:"labels,omitempty"`
}

// Service is one HvSocket service the guest exposes or dials. SYSTEM and
// Administrators may always bind and connect; Connect and Bind add accounts.
type Service struct {
	ID      string   `json:"id"`
	Connect []string `json:"connect,omitempty"`
	Bind    []string `json:"bind,omitempty"`
}

var (
	namePattern = regexp.MustCompile(`^bivouac-[a-z0-9][a-z0-9-]{0,54}$`)
	labelKey    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	labelValue  = regexp.MustCompile(`^[A-Za-z0-9._:+-]{0,128}$`)
	guidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	sidPattern  = regexp.MustCompile(`^S-1-[0-9]{1,14}(-[0-9]{1,10}){1,14}$`)
)

func (s Spec) Validate() error {
	if !namePattern.MatchString(s.Name) || strings.HasSuffix(s.Name, "-") {
		return errors.New("guest name must be bivouac- followed by lowercase letters, digits or hyphens")
	}
	if !localAbsolute(s.Image) || !strings.EqualFold(filepath.Ext(s.Image), ".vhdx") {
		return errors.New("guest image must be a local absolute VHDX path")
	}
	if s.CPU < 1 || s.CPU > 64 || s.MemoryMB < 1024 || s.MemoryMB > 256<<10 || s.MemoryMB%2 != 0 {
		return errors.New("guest needs 1-64 CPUs and an even 1024-262144 MiB of memory")
	}
	if len(s.Labels) > 8 {
		return errors.New("at most 8 labels")
	}
	for k, v := range s.Labels {
		if !labelKey.MatchString(k) || !labelValue.MatchString(v) {
			return errors.New("labels need short lowercase keys and plain values")
		}
	}
	if len(s.Services) > 8 {
		return errors.New("at most 8 HvSocket services")
	}
	seen := map[string]bool{}
	for _, service := range s.Services {
		if !guidPattern.MatchString(service.ID) || seen[service.ID] {
			return errors.New("HvSocket service IDs must be distinct lowercase GUIDs")
		}
		seen[service.ID] = true
		if len(service.Connect) > 8 || len(service.Bind) > 8 {
			return errors.New("at most 8 additional accounts per HvSocket service")
		}
		for _, sid := range append(append([]string{}, service.Connect...), service.Bind...) {
			if !sidPattern.MatchString(sid) {
				return errors.New("HvSocket accounts must be SID strings")
			}
		}
	}
	return nil
}

func localAbsolute(path string) bool {
	return len(path) > 3 && path[1:3] == `:\` && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path[2:], "\x00:*?\"<>|/")
}

// administrators is the base descriptor: only SYSTEM and Administrators.
const administrators = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

func descriptor(sids []string) string {
	var b strings.Builder
	b.WriteString(administrators)
	for _, sid := range sids {
		b.WriteString("(A;;FA;;;" + sid + ")")
	}
	return b.String()
}

// Guest storage file names inside the guest's journal directory.
const (
	diskFile         = "disk.vhdx"
	guestStateFile   = "vm.vmgs"
	runtimeStateFile = "vm.vmrs"
)

// document builds the creation document for a validated spec whose storage
// lives in dir. Its only NIC is the planned endpoint, if any; there is no
// share, clipboard, audio or display transport.
func document(owner string, s Spec, dir string, network *hostnet.Plan) hcs.ComputeSystem {
	services := map[string]hcs.HvSocketService{}
	for _, service := range s.Services {
		services[service.ID] = hcs.HvSocketService{BindSecurityDescriptor: descriptor(service.Bind), ConnectSecurityDescriptor: descriptor(service.Connect)}
	}
	devices := hcs.Devices{
		Scsi:         map[string]hcs.Scsi{"Primary": {Attachments: map[string]hcs.Attachment{"0": {Type: hcs.AttachmentVirtualDisk, Path: filepath.Join(dir, diskFile)}}}},
		VideoMonitor: &hcs.VideoMonitor{HorizontalResolution: 1024, VerticalResolution: 768},
		Keyboard:     &hcs.Keyboard{},
		Mouse:        &hcs.Mouse{},
	}
	if len(services) != 0 {
		devices.HvSocket = &hcs.HvSocket{HvSocketConfig: hcs.HvSocketConfig{ServiceTable: services}}
	}
	if network != nil {
		devices.NetworkAdapters = map[string]hcs.NetworkAdapter{network.EndpointID: {EndpointID: network.EndpointID, MacAddress: network.MAC}}
	}
	return hcs.ComputeSystem{
		Owner:                       owner,
		SchemaVersion:               hcs.Schema21(),
		TerminateOnLastHandleClosed: true,
		VirtualMachine: &hcs.VirtualMachine{
			Chipset: hcs.Chipset{Uefi: &hcs.Uefi{Console: "Default", ApplySecureBootTemplate: "Apply", SecureBootTemplateID: hcs.SecureBootMicrosoftWindows}},
			ComputeTopology: hcs.Topology{
				Memory:    hcs.Memory{SizeInMB: s.MemoryMB, AllowOvercommit: s.LazyMemory, EnableDeferredCommit: s.LazyMemory},
				Processor: hcs.Processor{Count: s.CPU},
			},
			Devices:          devices,
			SecuritySettings: &hcs.SecuritySettings{EnableTpm: true, Isolation: &hcs.Isolation{IsolationType: hcs.IsolationGuestStateOnly}},
			GuestState:       &hcs.GuestState{GuestStateFilePath: filepath.Join(dir, guestStateFile), RuntimeStateFilePath: filepath.Join(dir, runtimeStateFile)},
		},
	}
}
