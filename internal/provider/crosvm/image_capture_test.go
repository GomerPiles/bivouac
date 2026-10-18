package crosvm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImageCaptureRejectsUncleanOrUnownedNativeExit(t *testing.T) {
	for _, fault := range []string{"failed", "unowned", "foreign-image", "forced", "marker"} {
		t.Run(fault, func(t *testing.T) {
			b, r := recordedBackend(t, (&fakeProcesses{live: map[uint32]ProcessIdentity{}}).alive)
			state := NativeState{Supervisor: ProcessIdentity{PID: 40, Created: 7, Image: "fixture-supervisor"}, VM: ProcessIdentity{PID: 41, Created: 7, Image: r.Binary}, Phase: "exited", Empty: true, JobOwned: true}
			switch fault {
			case "failed":
				state.ExitCode = 1
			case "unowned":
				state.JobOwned = false
			case "foreign-image":
				state.VM.Image = "foreign"
			case "forced":
				if err := os.WriteFile(filepath.Join(r.Directory, "stop"), []byte("stop"), 0600); err != nil {
					t.Fatal(err)
				}
			case "marker":
				bad := r
				bad.Meta.ControllerID = "foreign"
				if err := writeJSON(r.Directory, ".bivouac-owner.json", bad); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeJSON(r.Directory, "native.json", state); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "Linux-Images")
			if _, err := b.CaptureRawImage(context.Background(), r.Name, output, strings.Repeat("a", 64)); err == nil {
				t.Fatal("unsafe capture accepted")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("refused capture created image output")
			}
		})
	}
}

func TestImageReceiptBindsSanitationShutdownAndSource(t *testing.T) {
	_, r := fixture(t)
	hash := strings.Repeat("a", 64)
	good := imageShutdownReceipt{Record: r, HelperSHA256: hash, Sanitized: true, ShutdownAcknowledged: true}
	if !validImageReceipt(good, r, hash) {
		t.Fatal("valid receipt rejected")
	}
	for _, fault := range []string{"controller", "helper", "sanitation", "shutdown"} {
		bad := good
		switch fault {
		case "controller":
			bad.Record.Meta.ControllerID = "foreign"
		case "helper":
			bad.HelperSHA256 = strings.Repeat("b", 64)
		case "sanitation":
			bad.Sanitized = false
		case "shutdown":
			bad.ShutdownAcknowledged = false
		}
		if validImageReceipt(bad, r, hash) {
			t.Fatal("mismatched image receipt accepted", fault)
		}
	}
}
