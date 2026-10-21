package manager

import (
	"context"
	"testing"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/state"
)

func TestHCSResourceAdmissionAndSpec(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		p := c.Providers["macos"]
		p.Type, p.VZ = "hcs", nil
		p.HCS = &config.HCS{Image: "windows", CPU: 4, MemoryGB: 8}
		c.Providers["macos"] = p
		c.Budget.ReserveCPU = 2
		c.Budget.ReserveMemoryGB = 2
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); h.m.Wait() }()
	h.m.accepting.Store(true)
	inst, err := h.m.launch(ctx, "macos", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if inst.CPU != 4 || inst.MemoryGB != 8 {
		t.Fatal("HCS launch did not reserve resources", inst.CPU, inst.MemoryGB)
	}
	h.eventually("HCS create", func() bool { return h.instanceNamed(state.PhaseBooting) != nil })
	h.m.cancelRuns(false)
	h.m.Wait()
	// Exercise recovery and accounting without a concurrent lifecycle mutating
	// the record or reading configuration changed below.
	if err := h.store.Put(inst); err != nil {
		t.Fatal(err)
	}
	pc := h.m.o.Config.Providers["macos"]
	spec, err := h.m.spec(inst, pc)
	if err != nil || spec.Baseline != "windows" || spec.CPU != 4 || spec.MemoryMB != 8192 {
		t.Fatal("HCS spec disagrees with reservation", spec, err)
	}
	for _, budget := range []string{"cpu", "memory"} {
		t.Run(budget, func(t *testing.T) {
			h.m.o.Host.CPUs = 10
			h.m.o.Host.MemoryBytes = 32 << 30
			if budget == "cpu" {
				h.m.o.Host.CPUs = 9
			} else {
				h.m.o.Host.MemoryBytes = 17 << 30
			}
			if n, _ := h.m.capacity(ctx, "macos"); n != 0 {
				t.Fatal("HCS host budget ignored", n)
			}
		})
	}
	// Recovery uses the recorded reservation even when configuration changes.
	pc.HCS.CPU, pc.HCS.MemoryGB = 1, 1
	spec, err = h.m.spec(inst, pc)
	if err != nil || spec.CPU != 4 || spec.MemoryMB != 8192 {
		t.Fatal("HCS recovery forgot frozen resources", spec, err)
	}
	if _, err := h.store.Update(inst.ID, func(i *state.Instance) { i.Phase = state.PhaseDeregistering }); err != nil {
		t.Fatal(err)
	}
	if n, _ := h.m.capacity(ctx, "macos"); n != 2 {
		t.Fatal("confirmed deletion did not release HCS resources", n)
	}
}
