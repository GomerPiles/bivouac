package crosvm

import (
	"context"
	"errors"
	"testing"

	"github.com/GomerPiles/bivouac/internal/provider"
)

type admissionBackend struct {
	Backend
	record  Record
	status  provider.Status
	failure error
}

func (b *admissionBackend) Lookup(context.Context, string) (Record, provider.Status, error) {
	return b.record, b.status, nil
}
func (b *admissionBackend) Verify(context.Context, string) error { return b.failure }

type admissionGuest struct {
	Guest
	calls int
}

func (g *admissionGuest) StartRunner(context.Context, Record, []byte) error { g.calls++; return nil }

func TestJITRequiresCurrentOwnedNativePolicy(t *testing.T) {
	for _, change := range []string{"none", "controller", "disk", "metadata", "stopped", "policy"} {
		t.Run(change, func(t *testing.T) {
			o, r := fixture(t)
			b := &admissionBackend{record: r, status: provider.Status{Exists: true, Owned: true, Running: true, Meta: r.Meta}}
			g := &admissionGuest{}
			switch change {
			case "controller":
				b.record.Meta.ControllerID = "foreign"
			case "disk":
				b.record.Disk = o.Baseline
			case "metadata":
				b.status.Meta.InstanceID = "different"
			case "stopped":
				b.status.Running = false
			case "policy":
				b.failure = errors.New("host snapshot changed")
			}
			p, err := New(o, b, g)
			if err != nil {
				t.Fatal(err)
			}
			err = p.StartRunner(context.Background(), r.Name, []byte("synthetic-bounded-jit"))
			if change == "none" {
				if err != nil || g.calls != 1 {
					t.Fatal("valid native proof rejected")
				}
			} else if err == nil || g.calls != 0 {
				t.Fatal("JIT reached unowned or unverified guest")
			}
		})
	}
}
