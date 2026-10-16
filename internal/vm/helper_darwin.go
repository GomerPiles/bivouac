package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// connectTimeout bounds one guest vsock connection attempt.
const connectTimeout = 5 * time.Second

// RunHelper is `bivouac vm run`: it holds dir's lock, boots the VM, proxies
// agent socket connections to the guest agent's vsock port, and exits when
// the guest stops. SIGTERM or SIGINT powers the VM off at once: guests are
// disposable, so a guest shutdown only delays teardown (a macOS guest
// ignores the request). Killing the helper powers
// the VM off too, because the framework ends a VM whose owning process exits.
//
// Output is host-side status only; the guest console is never attached.
func RunHelper(ctx context.Context, opts RunOptions, log io.Writer) error {
	logf := func(format string, args ...any) {
		_, _ = fmt.Fprintf(log, "%s bivouac vm: %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
	}
	if err := opts.validate(); err != nil {
		return err
	}
	f, err := openFramework()
	if err != nil {
		return err
	}
	socket := opts.AgentSocket
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return err
	}
	lock, err := Acquire(opts.Dir)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()
	// Read the manifest only through the lock: reopening it would release
	// the lock.
	c, err := lock.Manifest()
	if err != nil {
		return err
	}
	diskSync, err := diskSyncMode(opts.Machine.DiskSync)
	if err != nil {
		return err
	}
	if err := opts.Machine.CheckGuest(c); err != nil {
		return err
	}

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	defer signal.Stop(signals)

	mopts := machineOptions{share: opts.Share, networkFD: -1, input: opts.Input, display: opts.Machine.Display.withDefaults(c.Display), diskSync: diskSync, nested: opts.Machine.Nested}
	var sn *softnet
	if opts.Softnet != nil {
		sn, err = startSoftnet(*opts.Softnet, c.MAC, log)
		if err != nil {
			return err
		}
		defer sn.stop()
		mopts.networkFD = sn.vmFD
	}
	m, err := newMachine(f, opts.Dir, c, mopts)
	if err != nil {
		return err
	}
	if err := m.start(); err != nil {
		return err
	}
	logf("started %s guest with %d CPUs and %d MiB", c.OS, c.CPU, c.MemoryMiB)

	// Holding the lock proves any existing socket file is stale: the socket
	// is named after this VM alone.
	_ = os.Remove(socket)
	listener, err := listenPrivate(socket)
	if err != nil {
		_ = m.stop()
		return err
	}
	defer func() { _ = os.Remove(socket) }()
	var conns sync.WaitGroup
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conns.Go(func() { m.proxy(conn, opts.AgentPort) })
		}
	}()
	defer func() { _ = listener.Close() }()

	var softnetDone <-chan struct{}
	if sn != nil {
		softnetDone = sn.done
	}
	cancelled := ctx.Done()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-cancelled:
			cancelled = nil
			_ = m.stop()
		case <-signals:
			logf("powering off")
			_ = m.stop()
		case <-softnetDone:
			logf("softnet exited; powering off")
			softnetDone = nil
			_ = m.stop()
		case <-tick.C:
		}
		switch m.state() {
		case stateStopped:
			logf("guest stopped")
			return nil
		case stateError:
			return errors.New("VM stopped with an error")
		}
	}
}

func listenPrivate(path string) (net.Listener, error) {
	// The VM directory is the owner's; the socket is created owner-only too.
	old := unix.Umask(0o177)
	l, err := net.Listen("unix", path)
	unix.Umask(old)
	return l, err
}

// proxy joins one host agent connection to a fresh guest vsock stream.
func (m *machine) proxy(host net.Conn, port uint32) {
	defer func() { _ = host.Close() }()
	if m.state() != stateRunning {
		return
	}
	guest, err := m.connect(port, connectTimeout)
	if err != nil {
		return
	}
	defer func() { _ = guest.Close() }()
	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(guest, host)
		if raw, err := guest.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) { _ = unix.Shutdown(int(fd), unix.SHUT_WR) })
		}
	})
	_, _ = io.Copy(host, guest)
	if c, ok := host.(*net.UnixConn); ok {
		_ = c.CloseWrite()
	}
	wg.Wait()
}

// softnet is the privileged packet filter process between the guest and
// vmnet, connected over a datagram socket pair with Softnet's end as its
// stdin, the interface Softnet defines.
type softnet struct {
	cmd  *exec.Cmd
	vmFD int
	done chan struct{}
}

func startSoftnet(o SoftnetOptions, mac string, log io.Writer) (*softnet, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	// Apple recommends a receive buffer of at least four times the send buffer.
	for _, fd := range fds {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
		unix.CloseOnExec(fd)
	}
	peer := os.NewFile(uintptr(fds[1]), "softnet")
	args := []string{"--vm-fd", "0", "--vm-mac-address", mac, "--block", o.Block}
	name := o.Binary
	if o.Sudo {
		name, args = "/usr/bin/sudo", append([]string{"-n", o.Binary}, args...)
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = peer, log, log
	if err := cmd.Start(); err != nil {
		_ = peer.Close()
		_ = unix.Close(fds[0])
		return nil, fmt.Errorf("start softnet: %w", err)
	}
	_ = peer.Close()
	s := &softnet{cmd: cmd, vmFD: fds[0], done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(s.done) }()
	return s, nil
}

func (s *softnet) stop() {
	select {
	case <-s.done:
	default:
		_ = s.cmd.Process.Signal(os.Interrupt)
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
			_ = s.cmd.Process.Kill()
			<-s.done
		}
	}
	_ = unix.Close(s.vmFD)
}
