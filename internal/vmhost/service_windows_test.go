//go:build windows

package vmhost

import (
	"strings"
	"testing"
)

func TestServiceDescriptorGrantsAccountsOnlyQueryStartStop(t *testing.T) {
	service := serviceDescriptor([]string{alice}, nil)
	if !strings.Contains(service, "(A;;CCLCSWRPWPLOCRRC;;;"+alice+")") || strings.Contains(service, "DC;;;"+alice) || strings.Contains(service, "WD;;;"+alice) {
		t.Fatal("service descriptor grants accounts more than query, start and stop", service)
	}
}

func TestSandboxAccountsCannotStopOrReconfigureSharedService(t *testing.T) {
	service := serviceDescriptor([]string{alice}, []string{alice, bob})
	if !strings.Contains(service, "(A;;0x20014;;;"+bob+")") || strings.Contains(service, "RPWPLOCRRC;;;"+bob) || strings.Count(service, alice) != 1 {
		t.Fatal("Sandbox capability changed shared-service authority")
	}
}
