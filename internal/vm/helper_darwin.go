package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/rootnet"
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
	bounded := &cappedLog{out: log, left: (1 << 20) - 8192, reserved: 8192}
	log = bounded
	terminal := "helper exited"
	var finalStats func() rootnet.Snapshot
	defer func() {
		if finalStats != nil {
			b, _ := json.Marshal(finalStats())
			bounded.terminal([]byte(fmt.Sprintf("%s bivouac vm: %s; final counters %s\n", time.Now().UTC().Format(time.RFC3339), terminal, b)))
		} else {
			bounded.terminal([]byte(terminal + "\n"))
		}
	}()
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

	mopts := machineOptions{share: opts.Share, networkFD: -1, networkMTU: opts.Network.WithDefaults().MTU, input: opts.Input, display: opts.Machine.Display.withDefaults(c.Display), diskSync: diskSync, nested: opts.Machine.Nested, seedDisk: opts.Machine.SeedDisk, receiptDisk: opts.Machine.ReceiptDisk}
	var networkDone <-chan error
	var networkUpdates <-chan struct{}
	var rootNetwork *networkProcess
	if opts.RootlessNetwork {
		// Cache capabilities belong to the host transport, for every guest OS.
		// Without an attached per-VM listener, the fixed endpoint fails closed.
		cachePath, revocationPath, err := rootlessCachePaths(opts.Dir)
		if err != nil {
			return err
		}
		network, vmFile, err := startRootless(ctx, c.MAC, cachePath, revocationPath, opts.Network, opts.CacheMaxConnections)
		if err != nil {
			return err
		}
		rootNetwork = network
		finalStats = network.Stats
		defer func() { network.Close(); _ = vmFile.Close() }()
		networkDone = network.done
		networkUpdates = network.updates
		mopts.networkFD = int(vmFile.Fd())
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

	cancelled := ctx.Done()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	forced := false
	var counterLog counterLogState
	networkLog := slog.New(slog.NewJSONHandler(log, nil))
	for {
		select {
		case <-cancelled:
			cancelled = nil
			forced = true
			_ = m.stop()
		case <-signals:
			forced = true
			logf("powering off")
			_ = m.stop()
		case networkErr := <-networkDone:
			_ = networkErr
			_ = m.stop()
			terminal = "rootless network lost; guest retired"
			return errors.New(terminal)
		case <-networkUpdates:
			if rootNetwork != nil && counterLog.due(time.Now(), rootNetwork.Stats()) {
				networkLog.Info("rootless network counters", "counters", rootNetwork.Stats())
			}
		case <-tick.C:
		}
		switch m.state() {
		case stateStopped:
			terminal, err = stoppedResult(forced)
			logf("%s", terminal)
			return err
		case stateError:
			terminal = "VM stopped with an error"
			return errors.New(terminal)
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

// Endpoint paths are host capabilities. Guest OS does not select or widen them.
func rootlessCachePaths(dir string) (string, string, error) {
	store := Store(filepath.Dir(dir))
	name := filepath.Base(dir)
	payload, err := store.CacheSocketPath(name)
	if err != nil {
		return "", "", err
	}
	revocation, err := store.RevocationSocketPath(name)
	if err != nil {
		return "", "", err
	}
	return payload, revocation, nil
}
