package winrunner

import (
	"context"
	"os"
	"testing"
)

func TestGuestAdapterRefusesHostExecution(t *testing.T) {
	if err := RunGuest(context.Background(), "probe", os.Stdout); err == nil {
		t.Fatal("guest adapter ran on the host")
	}
}

func TestInstanceIDsAndRunnerDirsAreBounded(t *testing.T) {
	if id, err := instanceID("bivouac-windows-0a1b2c3d"); err != nil || id != "0a1b2c3d" {
		t.Fatal(id, err)
	}
	for _, name := range []string{"windows-0a1b2c3d", "bivouac-windows-0A1B2C3D", "bivouac-windows-0a1b2c3", "bivouac-windows-0a1b2c3g"} {
		if _, err := instanceID(name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	if !ValidRunnerDir(`C:\actions-runner`) || ValidRunnerDir(`C:\Windows\runner`) || ValidRunnerDir(`D:\runner`) || ValidRunnerDir(`C:\a\..\Windows`) {
		t.Fatal("runner directory bounds")
	}
}
