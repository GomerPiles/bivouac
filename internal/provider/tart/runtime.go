package tart

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/vm"
)

// Runtime is the VM layer under the provider. Tests substitute a recorder.
type Runtime interface {
	Clone(ctx context.Context, baseline, name string) error
	// Resize sets CPU count and memory (MiB) of a stopped VM; 0 keeps a value.
	Resize(ctx context.Context, name string, cpu, memoryMB int) error
	// Start launches the VM helper, whose host-side status goes to sink.
	Start(ctx context.Context, name string, launch Launch, sink io.Writer) (Process, error)
	// Exec runs argv through the guest agent. A stdout write error stops
	// the command and fails the call.
	Exec(ctx context.Context, name string, argv []string, stdin io.Reader, stdout io.Writer) error
	// Duplex attaches a binary-safe stream to argv's stdin and stdout.
	Duplex(ctx context.Context, name string, argv []string) (net.Conn, error)
	// Stop asks the guest to shut down and powers it off after timeout.
	Stop(ctx context.Context, name string, timeout time.Duration) error
	// Delete removes a stopped VM; fs.ErrNotExist when it is absent.
	Delete(ctx context.Context, name string) error
	List(ctx context.Context) ([]vm.Entry, error)
}

// Launch selects devices for one VM.
type Launch struct {
	Share   string // read-only host directory, or empty
	Input   bool   // keyboard and pointing devices
	Softnet *vm.SoftnetOptions
}

// local is the real Runtime: VM directories under a Tart home, each VM run
// by a `bivouac vm run` helper from the signed bivouac executable.
type local struct {
	home vm.Home
	exe  string
}

func newLocal(home string) (*local, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &local{home: vm.Home(home), exe: exe}, nil
}

func (l *local) Clone(_ context.Context, baseline, name string) error {
	return l.home.Clone(baseline, name)
}

func (l *local) Resize(_ context.Context, name string, cpu, memoryMB int) error {
	return l.home.Resize(name, cpu, memoryMB)
}

// helperArgs is the exact argument array the helper receives.
func (l *local) helperArgs(name string, launch Launch) []string {
	opts := vm.RunOptions{Dir: l.home.Dir(name), Share: launch.Share, Input: launch.Input, AgentPort: guestagent.Port, Softnet: launch.Softnet}
	return append([]string{"vm", "run"}, opts.Args()...)
}

func (l *local) Start(ctx context.Context, name string, launch Launch, sink io.Writer) (Process, error) {
	if _, err := l.home.SocketPath(name); err != nil {
		return nil, err
	}
	return (CLI{Binary: l.exe}).startInput(ctx, l.helperArgs(name, launch), nil, sink)
}

func (l *local) dial(name string) (guestagent.Dialer, error) {
	path, err := l.home.SocketPath(name)
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
// SIGTERM asks the guest to shut down, SIGKILL after timeout powers it off.
func (l *local) Stop(ctx context.Context, name string, timeout time.Duration) error {
	dir := l.home.Dir(name)
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
	return l.home.Delete(name)
}

func (l *local) List(context.Context) ([]vm.Entry, error) { return l.home.List() }

// absent reports whether a runtime error means the VM does not exist.
func absent(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, provider.ErrNotFound)
}
