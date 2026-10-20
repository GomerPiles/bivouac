//go:build windows

package vmhost

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/hcs"
)

const testService = "a5b0cafe-0001-4000-8000-000000000001"

func validSpec() Spec {
	return Spec{Name: "bivouac-lab-1", Image: `C:\Images\prepared.vhdx`, CPU: 2, MemoryMB: 4096, GPU: true,
		Services: []Service{{ID: testService, Connect: []string{"S-1-5-21-1-2-3-1001"}}}}
}

func TestSpecValidationRefusesUnsafeInput(t *testing.T) {
	if err := validSpec().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Spec){
		"foreign name":      func(s *Spec) { s.Name = "appsandbox-1" },
		"uppercase name":    func(s *Spec) { s.Name = "bivouac-Lab" },
		"trailing hyphen":   func(s *Spec) { s.Name = "bivouac-lab-" },
		"relative image":    func(s *Spec) { s.Image = `prepared.vhdx` },
		"UNC image":         func(s *Spec) { s.Image = `\\server\share\prepared.vhdx` },
		"stream image":      func(s *Spec) { s.Image = `C:\Images\prepared.vhdx:hidden` },
		"non-VHDX image":    func(s *Spec) { s.Image = `C:\Images\prepared.iso` },
		"no CPU":            func(s *Spec) { s.CPU = 0 },
		"too little memory": func(s *Spec) { s.MemoryMB = 512 },
		"odd memory":        func(s *Spec) { s.MemoryMB = 4097 },
		"braced service":    func(s *Spec) { s.Services[0].ID = "{" + testService + "}" },
		"duplicate service": func(s *Spec) { s.Services = append(s.Services, Service{ID: testService}) },
		"SDDL injection":    func(s *Spec) { s.Services[0].Connect = []string{"S-1-5-21-1)(A;;FA;;;WD"} },
		"well-known alias":  func(s *Spec) { s.Services[0].Bind = []string{"WD"} },
		"too many accounts": func(s *Spec) { s.Services[0].Connect = strings.Fields(strings.Repeat("S-1-5-21-1-2-3-1001 ", 9)) },
		"too many services": func(s *Spec) { s.Services = make([]Service, 9) },
	} {
		s := validSpec()
		s.Services = append([]Service(nil), s.Services...)
		mutate(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDocumentGrantsOnlyNamedAccountsAndBacksMemoryAsRequested(t *testing.T) {
	s := validSpec()
	doc := document("owner", s, `C:\Host\bivouac-lab-1`, nil)
	if !doc.TerminateOnLastHandleClosed || doc.Owner != "owner" {
		t.Fatal("guest lifetime is not bound to its VM host")
	}
	service := doc.VirtualMachine.Devices.HvSocket.HvSocketConfig.ServiceTable[testService]
	if service.ConnectSecurityDescriptor != "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)" || service.BindSecurityDescriptor != administrators || service.AllowWildcardBinds {
		t.Fatalf("unexpected service descriptor %+v", service)
	}
	if disk := doc.VirtualMachine.Devices.Scsi["Primary"].Attachments["0"]; disk.Path != `C:\Host\bivouac-lab-1\disk.vhdx` {
		t.Fatal("disk outside guest storage", disk.Path)
	}
	if doc.VirtualMachine.Devices.Plan9 != nil || doc.VirtualMachine.Devices.NetworkAdapters != nil {
		t.Fatal("unexpected share or network adapter")
	}
	if m := doc.VirtualMachine.ComputeTopology.Memory; m.AllowOvercommit || m.EnableDeferredCommit {
		t.Fatal("physically backed memory requested lazily")
	}
	s.LazyMemory = true
	if m := document("owner", s, `C:\Host\x`, nil).VirtualMachine.ComputeTopology.Memory; !m.AllowOvercommit || !m.EnableDeferredCommit {
		t.Fatal("lazy memory not requested")
	}
	s.Services = nil
	if document("owner", s, `C:\Host\x`, nil).VirtualMachine.Devices.HvSocket != nil {
		t.Fatal("empty HvSocket table emitted")
	}
}

func TestFirmwareBootsOnlyTheGuestDisk(t *testing.T) {
	doc := document("owner", validSpec(), `C:\Host\bivouac-lab-1`, nil)
	uefi := doc.VirtualMachine.Chipset.Uefi
	if uefi == nil || uefi.BootThis == nil || !uefi.StopOnBootFailure {
		t.Fatal("firmware may fall back to another boot device")
	}
	boot := *uefi.BootThis
	if boot.DeviceType != hcs.BootScsiDrive || boot.DiskNumber != 0 {
		t.Fatal("firmware boot entry is not a SCSI disk", boot)
	}
	if _, ok := doc.VirtualMachine.Devices.Scsi[boot.DevicePath].Attachments[strconv.Itoa(int(boot.DiskNumber))]; !ok {
		t.Fatal("firmware boot entry names no attached disk", boot)
	}
	b, err := json.Marshal(uefi)
	if err != nil || !strings.Contains(string(b), `"BootThis":{"DeviceType":"ScsiDrive","DevicePath":"Primary","DiskNumber":0}`) {
		t.Fatal("boot entry does not serialize with its disk number", string(b))
	}
}
