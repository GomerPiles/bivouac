package main

import (
	"testing"

	"github.com/GomerPiles/bivouac/internal/config"
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
