package vz

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"time"

	"github.com/GomerPiles/bivouac/internal/cachelink"
	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/vm"
)

// Runtime is the VM layer under the provider. Tests substitute a recorder.
type Runtime interface {
	// Clone copies baseline to name with its own MAC, CPU, and memory.
	Clone(ctx context.Context, baseline, name string, opts vm.CloneOptions) error
	// Start launches the VM helper, whose host-side status goes to sink.
	Start(ctx context.Context, name string, launch Launch, sink io.Writer) (Process, error)
	// Exec runs argv through the guest agent. A stdout write error stops
	// the command and fails the call.
	Exec(ctx context.Context, name string, argv []string, stdin io.Reader, stdout io.Writer) error
	// Duplex attaches a binary-safe stream to argv's stdin and stdout.
	Duplex(ctx context.Context, name string, argv []string) (net.Conn, error)
	// CacheListener binds the fixed private per-VM capability after ownership proof.
	CacheListeners(name string) (net.Listener, net.Listener, error)
	// Stop powers the VM off; timeout bounds the helper's exit.
	Stop(ctx context.Context, name string, timeout time.Duration) error
	// Delete removes a stopped VM; fs.ErrNotExist when it is absent.
	Delete(ctx context.Context, name string) error
	List(ctx context.Context) ([]vm.Entry, error)
}

// Launch selects devices and machine options for one VM.
type Launch struct {
	Share               string // read-only host directory, or empty
	Input               bool   // keyboard and pointing devices
	RootlessNetwork     bool
	Network             config.VZNetwork
	CacheMaxConnections int
	Machine             vm.MachineOptions
	// EngineGuest keeps the Linux engine member at MTU 1500 until its DHCP
	// MTU adoption is validated; the runner member uses the configured MTU.
	EngineGuest bool
}

// local is the real Runtime: VM directories in bivouac's store, each VM run
// by a `bivouac vm run` helper from the signed bivouac executable.
type local struct {
	store vm.Store
	exe   string
}

func newLocal(store string) (*local, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &local{store: vm.Store(store), exe: exe}, nil
}

// check reports whether this executable can run VM helpers in this store.
func (l *local) check(ctx context.Context) error {
	if err := l.store.CheckSocketPath(); err != nil {
		return err
	}
	if err := vm.CheckEntitlement(ctx, l.exe); err != nil {
		return fmt.Errorf("%s: %w", l.exe, err)
	}
	return nil
}

func (l *local) Clone(_ context.Context, baseline, name string, opts vm.CloneOptions) error {
	return l.store.Clone(baseline, name, opts)
}

// helperArgs is the exact argument array the helper receives.
func (l *local) helperArgs(name string, launch Launch) ([]string, error) {
	socket, err := l.store.SocketPath(name)
	if err != nil {
		return nil, err
	}
	opts := vm.RunOptions{Dir: l.store.Dir(name), Share: launch.Share, Input: launch.Input, AgentPort: guestagent.Port, AgentSocket: socket, RootlessNetwork: launch.RootlessNetwork, Network: launch.Network, CacheMaxConnections: launch.CacheMaxConnections, Machine: launch.Machine}
	return append([]string{"vm", "run"}, opts.Args()...), nil
}

func (l *local) Start(ctx context.Context, name string, launch Launch, sink io.Writer) (Process, error) {
	args, err := l.helperArgs(name, launch)
	if err != nil {
		return nil, err
	}
	return (CLI{Binary: l.exe}).startInput(ctx, args, nil, sink)
}

func (l *local) dial(name string) (guestagent.Dialer, error) {
	path, err := l.store.SocketPath(name)
	if err != nil {
		return nil, err
	}
	return guestagent.DialUnix(path), nil
}

func (l *local) Exec(ctx context.Context, name string, argv []string, stdin io.Reader, stdout io.Writer) error {
	dial, err := l.dial(name)
	if err != nil {
		return err
	}
	return guestagent.Run(ctx, dial, argv, stdin, stdout)
}

func (l *local) Duplex(ctx context.Context, name string, argv []string) (net.Conn, error) {
	dial, err := l.dial(name)
	if err != nil {
		return nil, err
	}
	return guestagent.Duplex(ctx, dial, argv)
}

// Stop signals the VM's helper, proven by its lock and its arguments:
// SIGTERM powers the VM off; SIGKILL after timeout ends a helper that hangs.
func (l *local) Stop(ctx context.Context, name string, timeout time.Duration) error {
	dir := l.store.Dir(name)
	pid, err := vm.HelperPID(dir)
	if err != nil || pid == 0 {
		return err
	}
	if err := terminate(pid, false); err != nil {
		return fmt.Errorf("stop VM helper: %w", err)
	}
	if l.waitStopped(ctx, dir, timeout) {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if pid, err = vm.HelperPID(dir); err != nil || pid == 0 {
		return err
	}
	if err := terminate(pid, true); err != nil {
		return fmt.Errorf("kill VM helper: %w", err)
	}
	if l.waitStopped(ctx, dir, 10*time.Second) {
		return nil
	}
	return errors.New("VM still running after its helper was killed")
}

func (l *local) waitStopped(ctx context.Context, dir string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if pid, err := vm.Holder(dir); err == nil && pid == 0 {
			return true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (l *local) Delete(_ context.Context, name string) error {
	return l.store.Delete(name)
}

func (l *local) List(context.Context) ([]vm.Entry, error) { return l.store.List() }

// absent reports whether a runtime error means the VM does not exist.
func absent(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, provider.ErrNotFound)
}

// ProveIsolation checks the live lock holder's launch, including its rootless network, rather than trusting mutable provider metadata for adoption.
func (l *local) ProveIsolation(name, policy string) error {
	return vm.ProveIsolation(l.store.Dir(name), policy)
}

func (l *local) CacheListeners(name string) (net.Listener, net.Listener, error) {
	payload, err := l.store.ListenCache(name, cachelink.Payload)
	if err != nil {
		return nil, nil, err
	}
	revocation, err := l.store.ListenCache(name, cachelink.Revocation)
	if err != nil {
		_ = payload.Close()
		return nil, nil, err
	}
	return payload, revocation, nil
}
