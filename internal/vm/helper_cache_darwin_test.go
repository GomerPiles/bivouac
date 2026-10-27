package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootlessCacheCapabilitiesAreGuestOSIndependent(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "biv-cache-os-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	store := Store(dir)
	for _, guestOS := range []string{"darwin", "linux"} {
		name := "bivouac-fixture-" + guestOS
		clone := store.Dir(name)
		if err := os.Mkdir(clone, 0700); err != nil {
			t.Fatal(err)
		}
		manifest := testManifest()
		if guestOS == "linux" {
			manifest.OS, manifest.MacOS = "linux", nil
		}
		if err := WriteManifest(clone, manifest); err != nil {
			t.Fatal(err)
		}
		payload, revocation, err := rootlessCachePaths(clone)
		if err != nil {
			t.Fatal(err)
		}
		wantPayload, err := store.CacheSocketPath(name)
		if err != nil {
			t.Fatal(err)
		}
		wantRevocation, err := store.RevocationSocketPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if payload == "" || revocation == "" || payload == revocation || payload != wantPayload || revocation != wantRevocation {
			t.Fatal("guest OS disabled or changed host cache capability paths")
		}
	}
	if _, _, err := rootlessCachePaths(filepath.Join(dir, strings.Repeat("v", 150), "bivouac-fixture")); err == nil {
		t.Fatal("invalid socket path accepted")
	}
}
