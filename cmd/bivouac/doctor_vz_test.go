package main

import (
	"testing"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider/vz"
	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

func TestDoctorVZSlotsApplyOnlyToDarwinGuests(t *testing.T) {
	for _, guestOS := range []string{"darwin", "linux"} {
		for _, available := range []bool{false, true} {
			cfg := config.VZ{HostVMLimit: 2, ForeignSlots: 2}
			if available {
				cfg.ForeignSlots = 1
			}
			count := 0
			doctorVZSlots("fixture", guestOS, cfg, func(level, name, detail string) {
				count++
				if name != "slots fixture" || detail == "" || (level == "PASS") != available {
					t.Fatal("Darwin slot report changed")
				}
			})
			if (count == 1) != (guestOS == "darwin") {
				t.Fatal("doctor applied Apple slots to Linux guests")
			}
		}
	}
}

func TestDoctorMissingDefaultLinuxBaselineBuildGuidance(t *testing.T) {
	cfg := config.VZ{Baseline: vzrecipe.DefaultName, GuestOS: "linux", Helper: "/opt/bivouac/linux-helper"}
	failed := false
	doctorVZBaseline(t.TempDir(), "fixture", cfg, vz.GuestRuntime{OS: "linux", Helper: cfg.Helper}, func(level, name, detail string) {
		if level != "FAIL" || name != "baseline fixture" || detail != "default Linux baseline is missing; run `bivouac vz build-baseline --provider fixture`" {
			t.Fatal("doctor guidance differs", detail)
		}
		failed = true
	})
	if !failed {
		t.Fatal("doctor omitted missing baseline")
	}
}
