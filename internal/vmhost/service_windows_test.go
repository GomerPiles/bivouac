//go:build windows

package vmhost

import (
	"strings"
	"testing"
)

func TestServiceDescriptorGrantsAccountsOnlyQueryStartStop(t *testing.T) {
	service := serviceDescriptor([]string{alice})
	if !strings.Contains(service, "(A;;CCLCSWRPWPLOCRRC;;;"+alice+")") || strings.Contains(service, "DC;;;"+alice) || strings.Contains(service, "WD;;;"+alice) {
		t.Fatal("service descriptor grants accounts more than query, start and stop", service)
	}
}
