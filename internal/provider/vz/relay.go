package vz

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/engine"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/vm"
)

// RelayPlan contains no credentials. It selects one recorded pair, never an
// endpoint supplied by a workflow. The subprocess opens no host network socket.
type RelayPlan struct {
	StatePath, Store                               string
	Name, InstanceID, ControllerID, Engine, Policy string
}

func (r RelayPlan) verifyRecord() error {
	if !strings.HasPrefix(r.Name, config.NamePrefix) || strings.ContainsAny(r.Name, "/\\ \t\r\n") || r.InstanceID == "" || r.ControllerID == "" {
		return provider.ErrNotOwned
	}
	if _, err := engine.Socket(r.Engine); err != nil {
		return err
	}
	data, err := os.ReadFile(r.StatePath)
	if err != nil {
		return provider.ErrNotOwned
	}
	var f state.File
	if json.Unmarshal(data, &f) != nil || f.ControllerID != r.ControllerID {
		return provider.ErrNotOwned
	}
	i := f.Instances[r.InstanceID]
	if i == nil || i.ID != r.InstanceID || i.Name != r.Name || i.EngineName != r.Name+"-engine" || i.ContainerEngine != r.Engine || i.Phase == state.PhaseDeregistering {
		return provider.ErrNotOwned
	}
	return nil
}

func (r RelayPlan) verify() error {
	if err := r.verifyRecord(); err != nil {
		return err
	}
	p := Provider{store: vm.Store(r.Store), controllerID: r.ControllerID}
	a, ok := p.readMeta(r.Name)
	if !ok || a.ControllerID != r.ControllerID || a.InstanceID != r.InstanceID || a.EngineName != r.Name+"-engine" || a.ParentName != "" || a.NetworkPolicy != r.Policy {
		return provider.ErrNotOwned
	}
	b, ok := p.readMeta(r.Name + "-engine")
	if !ok || b.ControllerID != r.ControllerID || b.InstanceID != r.InstanceID || b.ParentName != r.Name || b.EngineName != "" || b.NetworkPolicy != r.Policy {
		return provider.ErrNotOwned
	}
	return nil
}

// RunRelay is a detached supervisor. Guest frames cannot select commands, paths,
// VM names or host sockets. Transport loss or host network changes retire the
// recorded pair. This also handles a controller crash during a running job.
func RunRelay(ctx context.Context, input io.Reader) error {
	var r RelayPlan
	d := json.NewDecoder(io.LimitReader(input, 64<<10))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return errors.New("invalid container relay plan")
	}
	if err := r.verify(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	rt, err := newLocal(r.Store)
	if err != nil {
		return err
	}
	defer func() {
		stopCtx, done := context.WithTimeout(context.Background(), 40*time.Second)
		defer done()
		for _, name := range []string{r.Name, r.Name + "-engine"} {
			// A missing sibling must not leak a proven surviving member. Each
			// stop independently requires its own record, prefix, and marker.
			if r.verifyRecord() != nil {
				return
			}
			p := Provider{store: vm.Store(r.Store)}
			m, ok := p.readMeta(name)
			if !ok || m.ControllerID != r.ControllerID || m.InstanceID != r.InstanceID {
				continue
			}
			if name == r.Name {
				if m.EngineName != r.Name+"-engine" || m.ParentName != "" {
					continue
				}
			} else {
				if m.ParentName != r.Name || m.EngineName != "" {
					continue
				}
			}
			_ = rt.Stop(stopCtx, name, time.Second)
		}
	}()
	policy, err := NetworkPolicy()
	if err != nil || policy != r.Policy {
		return errors.New("host network changed before relay startup")
	}
	mac, err := rt.Duplex(ctx, r.Name, []string{engine.GuestHelper, "engine", "listen"})
	if err != nil {
		return err
	}
	defer func() { _ = mac.Close() }()
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				policy, err := NetworkPolicy()
				if err != nil || policy != r.Policy || r.verify() != nil {
					cancel()
					return
				}
				checkCtx, done := context.WithTimeout(ctx, 5*time.Second)
				vms, err := rt.List(checkCtx)
				done()
				macRunning, linuxRunning := false, false
				for _, v := range vms {
					if v.Name == r.Name {
						macRunning = v.Running
					}
					if v.Name == r.Name+"-engine" {
						linuxRunning = v.Running
					}
				}
				if err != nil || !macRunning || !linuxRunning {
					cancel()
					return
				}
			}
		}
	}()
	return engine.Relay(ctx, mac, func(ctx context.Context) (net.Conn, error) {
		if r.verify() != nil {
			return nil, provider.ErrNotOwned
		}
		return rt.Duplex(ctx, r.Name+"-engine", []string{engine.GuestHelper, "engine", "dial", r.Engine})
	})
}
