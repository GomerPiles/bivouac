package main

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestLinuxGuestKeyPreservesConfiguredAndDefaultPaths(t *testing.T) {
	const configured = `D:\Keys\linux`
	if got, err := linuxGuestKey(configured); err != nil || got != configured {
		t.Fatal("configured key changed", err)
	}
	if runtime.GOOS != "windows" {
		if _, err := linuxGuestKey(""); err == nil {
			t.Fatal("default key accepted on a non-Windows host")
		}
		return
	}
	base := t.TempDir()
	t.Setenv("ProgramData", base)
	if got, err := linuxGuestKey(""); err != nil || got != filepath.Join(base, "AppSandbox", "ssh", "id_appsandbox") {
		t.Fatal("default key changed", err)
	}
	t.Setenv("ProgramData", "")
	if _, err := linuxGuestKey(""); err == nil {
		t.Fatal("missing ProgramData accepted")
	}
}
