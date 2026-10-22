package manager

import (
	"context"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/hostinfo"
	"github.com/GomerPiles/bivouac/internal/state"
)

func TestWindowsReservationSurvivesResourceConfigChanges(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Budget.ReserveCPU = 2
		p := c.Providers["macos"]
		p.Type = "hcs"
		p.VZ = nil
		p.HCS = &config.HCS{Image: "ci-template", CPU: 4, MemoryGB: 8}
		c.Providers["macos"] = p
	})
	h.m.o.Host.CPUs = 6
	instance := &state.Instance{ID: "1234abcd", Provider: "macos", Name: "bivouac-macos-1234abcd", CPU: 4, MemoryGB: 8, Phase: state.PhaseRunning, CreatedAt: time.Now()}
	if err := h.store.Put(instance); err != nil {
		t.Fatal(err)
	}
	p := h.m.o.Config.Providers["macos"]
	p.HCS.CPU = 1
	p.HCS.MemoryGB = 1
	h.m.o.Config.Providers["macos"] = p
	if n, _ := h.m.rawCapacity(context.Background(), "macos"); n != 0 {
		t.Fatal("live Windows resources were recomputed from new config")
	}
	spec, err := h.m.spec(instance, p)
	if err != nil || spec.CPU != 4 || spec.MemoryMB != 8192 {
		t.Fatal("recovery forgot frozen Windows resources")
	}
	if _, err := h.store.Update(instance.ID, func(i *state.Instance) { i.Phase = state.PhaseDeregistering }); err != nil {
		t.Fatal(err)
	}
	if n, _ := h.m.rawCapacity(context.Background(), "macos"); n != 2 {
		t.Fatal("confirmed Windows deletion did not release resources")
	}
}

// Crosvm lists a record it cannot prove as a running
// prefixed foreign guest. Its record already holds the slot: capacity counts
// it once, and status does not also report it as unmanaged.
func TestUnprovableRecordCountsOnce(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Budget.MaxInstances = 4
		p := c.Providers["macos"]
		p.Type = "crosvm"
		p.MaxInstances = 4
		p.VZ = nil
		p.Crosvm = &config.Crosvm{BaselineName: "ci-template", CPU: 4, MemoryGB: 8}
		c.Providers["macos"] = p
	})
	h.m.o.Host = hostinfo.Info{CPUs: 32, MemoryBytes: 64 << 30}
	instance := &state.Instance{ID: "1234abcd", Provider: "macos", Name: "bivouac-macos-1234abcd", CPU: 4, MemoryGB: 8, Phase: state.PhaseRunning, CreatedAt: time.Now()}
	if err := h.store.Put(instance); err != nil {
		t.Fatal(err)
	}
	h.fp.AddForeign(instance.Name)
	if n, foreign := h.m.rawCapacity(context.Background(), "macos"); n != 1 || foreign != 0 {
		t.Fatalf("capacity %d, foreign %d: unprovable record counted twice", n, foreign)
	}
	h.fp.AddForeign("bivouac-macos-87654321")
	if n, foreign := h.m.rawCapacity(context.Background(), "macos"); n != 0 || foreign != 1 {
		t.Fatalf("capacity %d, foreign %d: unrecorded prefixed guest ignored", n, foreign)
	}
	h.m.writeStatus(context.Background(), control.ModeOn)
	s, err := h.files.ReadStatus()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Unmanaged) != 1 || s.Unmanaged[0] != "macos: bivouac-macos-87654321" || len(s.Guests) != 1 {
		t.Fatalf("unmanaged %v, guests %v", s.Unmanaged, s.Guests)
	}
}
