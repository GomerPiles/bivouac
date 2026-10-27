package vm

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/cachelink"
	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/dnsproxy"
	"github.com/GomerPiles/bivouac/internal/macnetwork"
	"github.com/GomerPiles/bivouac/internal/rootnet"
)

// RunNetwork is the private, credential-free child entry point. The parent
// passes only the Ethernet socket, an owner-lifetime pipe, a numeric report
// pipe, a cache-only descriptor broker, and a separate DNS capability. Guest
// bytes are not consumed until the sandbox and stack are ready.
func RunNetwork(ctx context.Context, mac string, settings config.VZNetwork) error {
	settings = settings.WithDefaults()
	if err := settings.Validate(); err != nil {
		return err
	}
	if err := EnsureNetworkFDs(settings.MaxFlows + settings.DNSConcurrency() + 128); err != nil {
		return err
	}
	attachment := os.NewFile(3, "network-attachment")
	lifetime := os.NewFile(4, "network-owner")
	report := os.NewFile(5, "network-report")
	cacheControl := os.NewFile(6, "network-cache")
	dnsControl := os.NewFile(7, "network-dns")
	if attachment == nil || lifetime == nil || report == nil || cacheControl == nil || dnsControl == nil {
		return errors.New("network capabilities unavailable")
	}
	defer func() { _ = dnsControl.Close() }()
	defer func() { _ = attachment.Close(); _ = lifetime.Close(); _ = report.Close(); _ = cacheControl.Close() }()
	cacheClient, err := cachelink.NewClient(cacheControl)
	if err != nil {
		return err
	}
	defer func() { _ = cacheClient.Close() }()
	dnsClient, err := dnsproxy.NewClient(dnsControl, settings.DNSConcurrency())
	if err != nil {
		return err
	}
	defer func() { _ = dnsClient.Close() }()
	link, err := net.FileConn(attachment)
	if err != nil {
		return errors.New("network attachment unavailable")
	}
	defer func() { _ = link.Close() }()
	if err := rootnet.ApplySandbox(); err != nil {
		return err
	}
	if _, err := macnetwork.Policy(); err != nil {
		return errors.New("sandbox network policy unavailable")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var cacheDial func(context.Context, cachelink.Kind) (net.Conn, error)
	if cacheClient.Enabled() {
		cacheDial = cacheClient.Dial
	}
	network, err := rootnet.New(ctx, mac, cacheDial, dnsClient.Resolve, settings)
	if err != nil {
		return err
	}
	defer network.Close()
	done := make(chan struct{})
	go func() { defer close(done); var b [1]byte; _, _ = lifetime.Read(b[:]); cancel() }()
	// One readiness byte is distinct from fixed-size numeric reports.
	if _, err := report.Write([]byte{1}); err != nil {
		cancel()
		_ = lifetime.Close()
		<-done
		return errors.New("network readiness unavailable")
	}
	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if err := binary.Write(report, binary.LittleEndian, network.Stats()); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	err = network.Serve(link)
	cancel()
	_ = lifetime.Close()
	<-done
	<-statsDone
	_ = binary.Write(report, binary.LittleEndian, network.Stats())
	_ = report.Close()
	return err
}

type networkProcess struct {
	cache            *cachelink.Broker
	dns              *dnsproxy.Broker
	updates          chan struct{}
	cmd              *exec.Cmd
	lifetime, report *os.File
	done             chan error
	readerDone       chan struct{}
	mu               sync.Mutex
	stats            rootnet.Snapshot
	once             sync.Once
}

func (p *networkProcess) Stats() rootnet.Snapshot { p.mu.Lock(); defer p.mu.Unlock(); return p.stats }
func (p *networkProcess) Close() {
	p.once.Do(func() {
		_ = p.cache.Close()
		_ = p.dns.Close()
		_ = p.lifetime.Close()
		select {
		case err := <-p.done:
			_ = err
		case <-time.After(5 * time.Second):
			_ = p.cmd.Process.Kill()
			waitErr := <-p.done
			_ = waitErr
		}
		_ = p.report.Close()
		<-p.readerDone
	})
}
func startRootless(ctx context.Context, mac, cachePath, revocationPath string, settings config.VZNetwork, cacheLimit int) (*networkProcess, *os.File, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	return startNetworkProcess(ctx, exec.CommandContext(ctx, exe, append([]string{"vm", "network", mac}, NetworkArgs(settings)...)...), cachePath, revocationPath, settings, cacheLimit)
}
func startNetworkProcess(ctx context.Context, cmd *exec.Cmd, cachePath, revocationPath string, settings config.VZNetwork, cacheLimit int) (*networkProcess, *os.File, error) {
	settings = settings.WithDefaults()
	if err := settings.Validate(); err != nil {
		return nil, nil, err
	}
	if cacheLimit == 0 {
		cacheLimit = 256
	}
	if err := EnsureNetworkFDs(2*(cacheLimit+cachelink.MaxRevocationConnections) + settings.DNSConcurrency() + 128); err != nil {
		return nil, nil, err
	}
	fds, err := networkSocketpair(settings.MTU)
	if err != nil {
		return nil, nil, err
	}
	vmFile := os.NewFile(uintptr(fds[0]), "network-vm")
	childFile := os.NewFile(uintptr(fds[1]), "network-child")
	defer func() { _ = childFile.Close() }()
	lifetimeRead, lifetimeWrite, err := os.Pipe()
	if err != nil {
		_ = vmFile.Close()
		return nil, nil, err
	}
	defer func() { _ = lifetimeRead.Close() }()
	reportRead, reportWrite, err := os.Pipe()
	if err != nil {
		_ = vmFile.Close()
		_ = lifetimeWrite.Close()
		return nil, nil, err
	}
	defer func() { _ = reportWrite.Close() }()
	broker, cacheFile, err := cachelink.NewBroker(cachePath, revocationPath, cacheLimit)
	if err != nil {
		_ = vmFile.Close()
		_ = lifetimeWrite.Close()
		_ = reportRead.Close()
		return nil, nil, err
	}
	ownedBroker := false
	defer func() {
		_ = cacheFile.Close()
		if !ownedBroker {
			_ = broker.Close()
		}
	}()
	resolver := dnsproxy.Resolver{Overrides: settings.DNSServers}
	dnsBroker, dnsFile, err := dnsproxy.NewBroker(resolver.Resolve, settings.DNSConcurrency())
	if err != nil {
		_ = vmFile.Close()
		_ = lifetimeWrite.Close()
		_ = reportRead.Close()
		return nil, nil, err
	}
	defer func() { _ = dnsFile.Close() }()
	defer func() {
		if !ownedBroker {
			_ = dnsBroker.Close()
		}
	}()
	cmd.Dir = "/"
	cmd.Env = []string{"HOME=/"}
	cmd.ExtraFiles = []*os.File{childFile, lifetimeRead, reportWrite, cacheFile, dnsFile}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		_ = vmFile.Close()
		_ = lifetimeWrite.Close()
		_ = reportRead.Close()
		return nil, nil, errors.New("start sandboxed network child")
	}
	// Close parent copies before waiting; otherwise EOF would not prove loss.
	_ = childFile.Close()
	_ = lifetimeRead.Close()
	_ = reportWrite.Close()
	ownedBroker = true
	p := &networkProcess{cache: broker, dns: dnsBroker, cmd: cmd, lifetime: lifetimeWrite, report: reportRead, done: make(chan error, 1), readerDone: make(chan struct{}), updates: make(chan struct{}, 1)}
	go func() { err := cmd.Wait(); _ = broker.Close(); _ = dnsBroker.Close(); p.done <- err; close(p.done) }()
	ready := make(chan bool, 1)
	go func() {
		defer close(p.readerDone)
		var b [1]byte
		_, err := io.ReadFull(reportRead, b[:])
		ready <- err == nil && b[0] == 1
		if err != nil || b[0] != 1 {
			return
		}
		for {
			var stats rootnet.Snapshot
			if binary.Read(reportRead, binary.LittleEndian, &stats) != nil {
				return
			}
			p.mu.Lock()
			p.stats = stats
			p.mu.Unlock()
			select {
			case p.updates <- struct{}{}:
			default:
			}
		}
	}()
	select {
	case ok := <-ready:
		if ok {
			return p, vmFile, nil
		}
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
	}
	p.Close()
	_ = vmFile.Close()
	return nil, nil, errors.New("sandboxed network child unavailable")
}
