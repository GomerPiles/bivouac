package hcs

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

// adminOnly is the HvSocket descriptor the direct-HCS spike booted with.
const adminOnly = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

func spikeDocument(withMedia bool) ComputeSystem {
	devices := Devices{
		Scsi:         map[string]Scsi{"Primary": {Attachments: map[string]Attachment{"0": {Type: AttachmentVirtualDisk, Path: `C:\HCS\guest\disk.vhdx`}}}},
		VideoMonitor: &VideoMonitor{HorizontalResolution: 1024, VerticalResolution: 768},
		Keyboard:     &Keyboard{},
		Mouse:        &Mouse{},
		HvSocket: &HvSocket{HvSocketConfig: HvSocketConfig{ServiceTable: map[string]HvSocketService{
			"a5b0cafe-0001-4000-8000-000000000001": {BindSecurityDescriptor: adminOnly, ConnectSecurityDescriptor: adminOnly},
			"a5b0cafe-0007-4000-8000-000000000001": {BindSecurityDescriptor: adminOnly, ConnectSecurityDescriptor: adminOnly},
		}}},
	}
	if withMedia {
		devices.Scsi["Primary"].Attachments["1"] = Attachment{Type: AttachmentISO, Path: `C:\HCS\guest\setup-private\setup.iso`}
		devices.Plan9 = &Plan9{Shares: []Plan9Share{{Name: "AppSandbox.Drv.0", AccessName: "AppSandbox.Drv.0", Path: `C:\HCS\guest\drivers\0`, Port: 50001, Flags: Plan9ShareReadOnly}}}
	}
	return ComputeSystem{
		Owner:                       "owner",
		SchemaVersion:               Schema21(),
		TerminateOnLastHandleClosed: true,
		VirtualMachine: &VirtualMachine{
			Chipset:          Chipset{Uefi: &Uefi{Console: "Default", ApplySecureBootTemplate: "Apply", SecureBootTemplateID: SecureBootMicrosoftWindows}},
			ComputeTopology:  Topology{Memory: Memory{SizeInMB: 4096}, Processor: Processor{Count: 2}},
			Devices:          devices,
			SecuritySettings: &SecuritySettings{EnableTpm: true, Isolation: &Isolation{IsolationType: IsolationGuestStateOnly}},
			GuestState:       &GuestState{GuestStateFilePath: `C:\HCS\guest\vm.vmgs`, RuntimeStateFilePath: `C:\HCS\guest\vm.vmrs`},
		},
	}
}

// The typed document must stay byte-for-byte equivalent (as JSON values) to
// the untyped one that booted Windows guests with GPU-PV in live trials.
func TestDocumentMatchesLiveValidatedShape(t *testing.T) {
	const service = `{"BindSecurityDescriptor":"D:P(A;;FA;;;SY)(A;;FA;;;BA)","ConnectSecurityDescriptor":"D:P(A;;FA;;;SY)(A;;FA;;;BA)","AllowWildcardBinds":false}`
	const base = `{"SchemaVersion":{"Major":2,"Minor":1},"Owner":"owner","ShouldTerminateOnLastHandleClosed":true,"VirtualMachine":{` +
		`"Chipset":{"Uefi":{"Console":"Default","ApplySecureBootTemplate":"Apply","SecureBootTemplateId":"1734c6e8-3154-4dda-ba5f-a874cc483422"}},` +
		`"ComputeTopology":{"Memory":{"SizeInMB":4096},"Processor":{"Count":2}},` +
		`"Devices":{"Scsi":{"Primary":{"Attachments":{"0":{"Type":"VirtualDisk","Path":"C:\\HCS\\guest\\disk.vhdx"}%s}}},` +
		`"VideoMonitor":{"HorizontalResolution":1024,"VerticalResolution":768},` +
		`"HvSocket":{"HvSocketConfig":{"ServiceTable":{"a5b0cafe-0001-4000-8000-000000000001":` + service + `,"a5b0cafe-0007-4000-8000-000000000001":` + service + `}}},` +
		`"Keyboard":{},"Mouse":{}%s},` +
		`"SecuritySettings":{"EnableTpm":true,"Isolation":{"IsolationType":"GuestStateOnly"}},` +
		`"GuestState":{"GuestStateFilePath":"C:\\HCS\\guest\\vm.vmgs","RuntimeStateFilePath":"C:\\HCS\\guest\\vm.vmrs"}}}`
	for _, tc := range []struct {
		media bool
		want  string
	}{
		{false, fmt.Sprintf(base, "", "")},
		{true, fmt.Sprintf(base, `,"1":{"Type":"Iso","Path":"C:\\HCS\\guest\\setup-private\\setup.iso"}`,
			`,"Plan9":{"Shares":[{"Name":"AppSandbox.Drv.0","AccessName":"AppSandbox.Drv.0","Path":"C:\\HCS\\guest\\drivers\\0","Port":50001,"Flags":1}]}`)},
	} {
		got, err := json.Marshal(spikeDocument(tc.media))
		if err != nil {
			t.Fatal(err)
		}
		assertSameJSON(t, got, tc.want)
	}
}

func TestDefaultGPURequestMatchesLiveValidatedShape(t *testing.T) {
	got, err := json.Marshal(AssignDefaultGPU())
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, got, `{"ResourcePath":"VirtualMachine/ComputeTopology/Gpu","RequestType":"Update","Settings":{"AssignmentMode":"Default","AllowVendorExtension":true}}`)
}

func TestOnlyGracefulSuccessIsAGracefulExit(t *testing.T) {
	for _, tc := range []struct {
		status ExitStatus
		want   bool
	}{
		{ExitStatus{Status: 0, ExitType: ExitGraceful}, true},
		{ExitStatus{Status: 1, ExitType: ExitGraceful}, false},
		{ExitStatus{Status: 0, ExitType: "ForcedExit"}, false},
		{ExitStatus{Status: 0, ExitType: "UnexpectedExit"}, false},
		{ExitStatus{}, false},
	} {
		if tc.status.Graceful() != tc.want {
			t.Errorf("%+v graceful=%v", tc.status, !tc.want)
		}
	}
}

func assertSameJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatal("invalid expectation:", err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("document differs:\n got %s\nwant %s", got, want)
	}
}
