package manager

import (
	"context"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/fake"
	"github.com/GomerPiles/bivouac/internal/state"
)

// Apple's two-guest limit is per host. Guests of one vz provider, and
// owned guests without a record, use slots every vz provider sees.
func TestVZHostLimitSpansProviders(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Budget.MaxInstances = 4 })
	p := h.m.o.Config.Providers["macos"]
	tc := *p.VZ
	p.VZ = &tc
	p.ScaleSet = "bivouac-studio"
	h.m.o.Config.Providers["studio"] = p
	h.m.o.Providers["studio"] = fake.New("studio", "ctl-test")
	if n, _ := h.m.rawCapacity(context.Background(), "macos"); n != 2 {
		t.Fatalf("empty host capacity = %d", n)
	}
	if err := h.store.Put(&state.Instance{ID: "s1", Provider: "studio", Name: "bivouac-studio-s1", Phase: state.PhaseRunning, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if n, _ := h.m.rawCapacity(context.Background(), "macos"); n != 1 {
		t.Fatalf("another provider's guest ignored: %d", n)
	}
	// An owned running guest with no record (an orphan awaiting reconcile)
	// also occupies a slot.
	if err := h.fp.Create(context.Background(), provider.Spec{Name: "bivouac-studio-orphan", Meta: provider.Metadata{ControllerID: "ctl-test"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.fp.Start(context.Background(), "bivouac-studio-orphan", discard{}); err != nil {
		t.Fatal(err)
	}
	if n, _ := h.m.rawCapacity(context.Background(), "macos"); n != 0 {
		t.Fatalf("orphan ignored: %d", n)
	}
}

type discard struct{}

func (discard) Write(b []byte) (int, error) { return len(b), nil }
