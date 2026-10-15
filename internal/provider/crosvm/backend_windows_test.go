//go:build windows

package crosvm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/GomerPiles/bivouac/internal/provider"
	"golang.org/x/sys/windows"
)

func TestNativeCleanupRetainsMarkersUntilAllFilesAreGone(t *testing.T) {
	b, r := recordedBackend(t, sameProcess)
	path := filepath.Join(r.Directory, "unexpected-sentinel")
	if err := os.WriteFile(path, []byte("retain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(context.Background(), r.Name); err == nil {
		t.Fatal("unknown file erased")
	}
	if _, err := loadEnvelope(filepath.Join(r.Directory, "owner.json")); err != nil {
		t.Fatal("partial deletion lost ownership")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(context.Background(), r.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("instance directory remains")
	}
}

func TestNativeCleanupRejectsForgedMarkerAndPendingLaunch(t *testing.T) {
	for _, mode := range []string{"marker", "pending"} {
		t.Run(mode, func(t *testing.T) {
			b, r := recordedBackend(t, sameProcess)
			sentinel := filepath.Join(r.Directory, "disk.qcow2")
			if err := os.WriteFile(sentinel, []byte("never remove"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "marker":
				marker := r
				marker.Meta.ControllerID = "foreign"
				if err := writeJSON(r.Directory, ".bivouac-owner.json", marker); err != nil {
					t.Fatal(err)
				}
			case "pending":
				// A supervisor that has not journalled yet holds the instance lock.
				holdInstanceLock(t, r)
				if err := writeJSON(r.Directory, "launch.intent", true); err != nil {
					t.Fatal(err)
				}
			}
			if err := b.Delete(context.Background(), r.Name); err == nil {
				t.Fatal("unsafe deletion accepted")
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "never remove" {
				t.Fatal("unconfirmed resource was changed")
			}
			if mode == "marker" {
				if _, _, err := b.Lookup(context.Background(), r.Name); !errors.Is(err, provider.ErrNotOwned) {
					t.Fatal("forged marker accepted")
				}
			}
		})
	}
}

// After a reboot the recorded supervisor PID can belong to an unrelated live
// process. Its different creation time proves the recorded group is gone.
func TestNativeReusedPIDIsRecoveredNotRetained(t *testing.T) {
	b, r := recordedBackend(t, sameProcess)
	identity, live, err := Identity(windows.GetCurrentProcessId())
	if err != nil || !live {
		t.Fatal("test identity unavailable")
	}
	identity.Created++
	if live, err := sameProcess(identity); err != nil || live {
		t.Fatal("reused PID not reported as gone", live, err)
	}
	vm := ProcessIdentity{PID: identity.PID, Created: identity.Created, Image: r.Binary}
	if err := writeJSON(r.Directory, "native.json", NativeState{Supervisor: identity, VM: vm, Phase: "running", JobOwned: true}); err != nil {
		t.Fatal(err)
	}
	if _, status, err := b.Lookup(context.Background(), r.Name); err != nil || status.Running {
		t.Fatal("reused PID blocked lookup", err)
	}
	if _, _, err := b.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(context.Background(), r.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("instance directory remains")
	}
	// The same PID and creation time with another image is contradictory.
	identity.Created--
	identity.Image = filepath.Join(filepath.Dir(identity.Image), "other.exe")
	if _, err := sameProcess(identity); err == nil {
		t.Fatal("changed image for the same process accepted")
	}
}

func TestLaunchInputsDoNotOpenBaselineForReading(t *testing.T) {
	o := launchInputFixture(t)
	path, err := windows.UTF16PtrFromString(o.Baseline)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_WRITE, windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	if file, err := os.Open(o.Baseline); err == nil {
		_ = file.Close()
		t.Fatal("fixture did not deny baseline data reads")
	}
	if err := verifyLaunchInputs(o); err != nil {
		t.Fatal("launch verification attempted a baseline data read", err)
	}
}

func TestNativeInventoryDoesNotRaceOwnedDeletion(t *testing.T) {
	for range 16 {
		b, r := recordedBackend(t, sameProcess)
		deleted := make(chan error, 1)
		go func() { deleted <- b.Delete(context.Background(), r.Name) }()
		for range 16 {
			if _, _, err := b.List(context.Background()); err != nil {
				t.Fatal("inventory raced journal removal", err)
			}
		}
		if err := <-deleted; err != nil {
			t.Fatal(err)
		}
	}
}
