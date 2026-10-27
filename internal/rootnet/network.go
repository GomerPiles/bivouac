// Package rootnet is a bounded, rootless Ethernet-to-public-sockets network
// for guests on macOS hosts, independent of the guest OS.
package rootnet

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/cachelink"
	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/macnetwork"
	"github.com/GomerPiles/bivouac/internal/streamrelay"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const PolicyID = "rootless-sandbox-public-ipv4"

const Gateway = cachelink.Address
const Guest = "192.0.2.2"
const gatewayMAC = "\x02\x00\x00\x00\x00\x01"

type flow struct {
	conn    net.Conn
	address netip.Addr
}
type options struct {
	settings        config.VZNetwork
	udpIdle         time.Duration
	cacheSendBuffer int
	cacheDial       func(context.Context, cachelink.Kind) (net.Conn, error)
	refresh         func()
	tcpIdle         time.Duration
	allow           func(netip.Addr) bool
	dial            func(context.Context, string, string) (net.Conn, error)
	dnsExchange     func(context.Context, []byte) ([]byte, error)
}
type Network struct {
	wire            *packetLink
	stats           counters
	s               *stack.Stack
	link            *channel.Endpoint
	mac             net.HardwareAddr
	ctx             context.Context
	cancel          context.CancelFunc
	options         options
	mu              sync.Mutex
	activePublicTCP uint64 // guarded by mu; includes admission and pending dials
	activeUDP       uint64 // guarded by mu
	activeCache     uint64 // guarded by mu; payload only, excluding reserved CRL
	flows           map[net.Conn]netip.Addr
	slots           chan struct{}
	udpBuffers      sync.Pool
	udpGuestBuffers sync.Pool
	revocationSlots chan struct{}
	cacheFlows      map[net.Conn]struct{}
	dnsSlots        chan struct{}
	wg              sync.WaitGroup
	closed          bool
	once            sync.Once
}

func New(ctx context.Context, mac string, cacheDial func(context.Context, cachelink.Kind) (net.Conn, error), dnsExchange func(context.Context, []byte) ([]byte, error), settings config.VZNetwork) (*Network, error) {
	policy := macnetwork.NewCache()
	return newNetwork(ctx, mac, options{
		cacheDial:   cacheDial,
		allow:       policy.Allows,
		refresh:     policy.Refresh,
		dial:        (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		dnsExchange: dnsExchange, settings: settings,
	})
}
func newNetwork(parent context.Context, mac string, o options) (*Network, error) {
	address, err := net.ParseMAC(mac)
	if err != nil || len(address) != 6 {
		return nil, errors.New("invalid guest MAC")
	}
	o.settings = o.settings.WithDefaults()
	if err := o.settings.Validate(); err != nil {
		return nil, err
	}
	if o.tcpIdle <= 0 {
		o.tcpIdle = o.settings.TCPIdleTimeout.Duration
	}
	if o.udpIdle <= 0 {
		o.udpIdle = o.settings.UDPIdleTimeout.Duration
	}
	ctx, cancel := context.WithCancel(parent)
	n := &Network{mac: address, ctx: ctx, cancel: cancel, options: o, flows: map[net.Conn]netip.Addr{}, cacheFlows: map[net.Conn]struct{}{}, revocationSlots: make(chan struct{}, cachelink.MaxRevocationConnections), slots: make(chan struct{}, o.settings.MaxFlows), dnsSlots: make(chan struct{}, o.settings.DNSConcurrency())}
	n.udpBuffers.New = func() any { b := make([]byte, 65507); return &b }
	n.udpGuestBuffers.New = func() any { b := make([]byte, min(65507, o.settings.MTU-28)+1); return &b }
	n.link = channel.New(256, uint32(o.settings.MTU+14), tcpip.LinkAddress(gatewayMAC)) //nolint:gosec // Validated MTU is 1500..65535.
	n.wire = newPacketLink(ctx, n.link, dataQueueFrames, controlQueueFrames)
	// Protocol registration is the extension point for IPv6/ICMP. Keep each
	// family's link control and socket admission explicit; adding a protocol
	// here alone must never enable guest egress. Flow ownership uses netip.Addr
	// so a future admitted IPv6 flow can share the same bounded lifecycle.
	n.s = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	limit := o.settings.TCPBufferLimit()
	if err := n.s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: limit, Max: limit}); err != nil {
		n.Close()
		return nil, errors.New("configure TCP send memory bound")
	}
	if err := n.s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: limit, Max: limit}); err != nil {
		n.Close()
		return nil, errors.New("configure TCP receive memory bound")
	}
	if err := n.s.CreateNIC(1, ethernet.New(n.wire)); err != nil {
		n.Close()
		return nil, errors.New("create isolated NIC")
	}
	ip := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	if err := n.s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: ip, PrefixLen: 24}}, stack.AddressProperties{}); err != nil {
		n.Close()
		return nil, errors.New("address isolated NIC")
	}
	// A userspace router must accept guest destinations it does not own. This
	// never creates a host interface, link, port forward, or loopback mapping.
	_ = n.s.SetPromiscuousMode(1, true)
	_ = n.s.SetSpoofing(1, true)
	// Spoofing is required for replies from public destinations, but must never
	// make ARP claim the guest's own address during duplicate-address detection.
	if err := n.s.AddStaticNeighbor(1, ipv4.ProtocolNumber, tcpip.AddrFrom4([4]byte{192, 0, 2, 2}), tcpip.LinkAddress(address)); err != nil {
		n.Close()
		return nil, errors.New("pin isolated guest neighbor")
	}
	n.s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	n.s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(n.s, 0, o.settings.MaxFlows+cachelink.MaxRevocationConnections+o.settings.DNSConcurrency(), n.tcp).HandlePacket)
	n.s.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(n.s, n.udp).HandlePacket)
	if n.options.dnsExchange != nil {
		if err := n.startDNS(); err != nil {
			n.Close()
			return nil, err
		}
	}
	n.wg.Go(n.revalidate)
	return n, nil
}
func (n *Network) acquireDNS() bool { return n.acquireSlot(n.dnsSlots) }
func (n *Network) releaseDNS()      { <-n.dnsSlots; n.wg.Done() }
func (n *Network) acquireSlot(slots chan struct{}) bool {
	return n.acquireCountedSlot(slots, nil)
}
func (n *Network) acquireCountedSlot(slots chan struct{}, gauge *uint64) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return false
	}
	select {
	case slots <- struct{}{}:
		if gauge != nil {
			*gauge++
		}
		n.wg.Add(1)
		return true
	default:
		return false
	}
}
func (n *Network) releaseCountedSlot(slots chan struct{}, gauge *uint64) {
	n.mu.Lock()
	<-slots
	if gauge != nil {
		*gauge--
	}
	n.mu.Unlock()
	n.wg.Done()
}
func ipv4Addr(a tcpip.Address) netip.Addr { return netip.AddrFrom4(a.As4()) }
func (n *Network) track(c net.Conn, a netip.Addr) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		_ = c.Close()
		return false
	}
	n.flows[c] = a
	return true
}
func (n *Network) untrack(c net.Conn) { n.mu.Lock(); delete(n.flows, c); n.mu.Unlock(); _ = c.Close() }
func (n *Network) tcp(r *tcp.ForwarderRequest) {
	id := r.ID()
	var kind cachelink.Kind
	if n.options.cacheDial != nil && id.LocalAddress == tcpip.AddrFrom4([4]byte{192, 0, 2, 1}) {
		switch id.LocalPort {
		case cachelink.Port:
			kind = cachelink.Payload
		case cachelink.RevocationPort:
			kind = cachelink.Revocation
		}
	}
	isCache := kind != 0
	slots := n.slots
	gauge := &n.activePublicTCP
	if kind == cachelink.Payload {
		gauge = &n.activeCache
	}
	if kind == cachelink.Revocation {
		slots = n.revocationSlots
		gauge = nil
	}
	if !n.acquireCountedSlot(slots, gauge) {
		n.stats.flowLimit.Add(1)
		r.Complete(true)
		return
	}
	go func() {
		defer n.releaseCountedSlot(slots, gauge)
		a := ipv4Addr(id.LocalAddress)
		if !isCache && !n.options.allow(a) {
			n.stats.admissionDenied.Add(1)
			r.Complete(true)
			return
		}
		var upstream net.Conn
		var err error
		if isCache {
			upstream, err = n.options.cacheDial(n.ctx, kind)
		} else {
			upstream, err = n.options.dial(n.ctx, "tcp4", net.JoinHostPort(a.String(), port(id.LocalPort)))
		}
		if err != nil {
			n.stats.dialFailed.Add(1)
			r.Complete(true)
			return
		}
		n.mu.Lock()
		trackedOK := !n.closed
		if trackedOK {
			if isCache {
				n.cacheFlows[upstream] = struct{}{}
			} else {
				n.flows[upstream] = a
			}
		}
		n.mu.Unlock()
		if !trackedOK {
			_ = upstream.Close()
			r.Complete(true)
			return
		}
		tracked := upstream
		defer func() {
			n.mu.Lock()
			delete(n.cacheFlows, tracked)
			delete(n.flows, tracked)
			n.mu.Unlock()
			_ = tracked.Close()
		}()
		var q waiter.Queue
		ep, e := r.CreateEndpoint(&q)
		r.Complete(e != nil)
		if e != nil {
			return
		}
		// Cache relays emit TLS records through several bounded stream hops.
		// Avoid coupling their short writes to the guest's delayed ACK timer.
		// Both public and cache streams retain the stack's budget-derived limits.
		if isCache {
			ep.SocketOptions().SetDelayOption(false)
			// Benchmarks can request smaller buffers within the same budget.
			// Production keeps the budget-derived defaults.
			if n.options.cacheSendBuffer > 0 {
				ep.SocketOptions().SetSendBufferSize(int64(min(n.options.cacheSendBuffer, n.options.settings.TCPBufferLimit())), true)
			}
		}
		idle := newIdleState(n.options.tcpIdle)
		var guest net.Conn = &idleConn{Conn: gonet.NewTCPConn(&q, ep), state: idle}
		upstream = &idleConn{Conn: upstream, state: idle}
		idle.setConnections(guest, upstream)
		defer func() { _ = guest.Close() }()
		stop := context.AfterFunc(n.ctx, func() { _ = upstream.Close(); _ = guest.Close() })
		defer stop()
		streamrelay.Copy(upstream, guest)
	}()
}
func port(p uint16) string {
	var b [5]byte
	i := len(b)
	for {
		i--
		b[i] = byte(p%10) + '0'
		p /= 10
		if p == 0 {
			return string(b[i:])
		}
	}
}
func (n *Network) udp(r *udp.ForwarderRequest) bool {
	id := r.ID()
	a := ipv4Addr(id.LocalAddress)
	if !n.acquireCountedSlot(n.slots, &n.activeUDP) {
		n.stats.flowLimit.Add(1)
		return true
	}
	if !n.options.allow(a) {
		n.stats.admissionDenied.Add(1)
		n.releaseCountedSlot(n.slots, &n.activeUDP)
		return true
	}
	var q waiter.Queue
	ep, e := r.CreateEndpoint(&q)
	if e != nil {
		n.releaseCountedSlot(n.slots, &n.activeUDP)
		return true
	}
	go func() {
		defer n.releaseCountedSlot(n.slots, &n.activeUDP)
		guest := gonet.NewUDPConn(&q, ep)
		defer func() { _ = guest.Close() }()
		if !n.options.allow(a) {
			return
		}
		upstream, err := n.options.dial(n.ctx, "udp4", net.JoinHostPort(a.String(), port(id.LocalPort)))
		if err != nil {
			n.stats.dialFailed.Add(1)
			return
		}
		if !n.track(upstream, a) {
			return
		}
		defer n.untrack(upstream)
		ctx, cancel := context.WithCancel(n.ctx)
		activity := make(chan struct{}, 1)
		watchDone := make(chan struct{})
		go func() {
			defer cancel()
			defer close(watchDone)
			defer func() { _ = guest.Close(); _ = upstream.Close() }()
			timer := time.NewTimer(n.options.udpIdle)
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					return
				case <-activity:
					timer.Reset(n.options.udpIdle)
				}
			}
		}()
		defer func() { cancel(); <-watchDone }()
		touch := func() {
			select {
			case activity <- struct{}{}:
			default:
			}
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer cancel()
			entry, ready := waiter.NewChannelEntry(waiter.ReadableEvents)
			q.EventRegister(&entry)
			defer q.EventUnregister(&entry)
			for {
				if ep.Readiness(waiter.ReadableEvents) == 0 {
					select {
					case <-ready:
					case <-ctx.Done():
						return
					}
					continue
				}
				buffer := n.udpGuestBuffers.Get().(*[]byte)
				count, err := guest.Read(*buffer)
				if err == nil && !n.options.allow(a) {
					err = net.ErrClosed
				}
				if err == nil && count < len(*buffer) {
					touch()
					_, err = upstream.Write((*buffer)[:count])
				}
				n.udpGuestBuffers.Put(buffer)
				if err != nil {
					return
				}
			}
		}()
		for {
			// Wait before borrowing the full datagram buffer. Idle sockets retain no
			// per-flow payload buffer; only this goroutine consumes upstream datagrams.
			if err := waitUDPReadable(upstream); err != nil {
				break
			}
			buffer := n.udpBuffers.Get().(*[]byte)
			count, err := upstream.Read(*buffer)
			if err == nil {
				touch()
				_, err = guest.Write((*buffer)[:count])
			}
			n.udpBuffers.Put(buffer)
			if err != nil || id.LocalPort == 53 || id.LocalPort == 123 {
				break
			}
		}
		cancel()
		<-done
	}()
	return true
}
func (n *Network) revalidate() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}
		if n.options.refresh != nil {
			n.options.refresh()
		}
		n.mu.Lock()
		items := make([]flow, 0, len(n.flows))
		for c, a := range n.flows {
			items = append(items, flow{c, a})
		}
		n.mu.Unlock()
		for _, f := range items {
			if !n.options.allow(f.address) {
				_ = f.conn.Close()
			}
		}
	}
}

// Input accepts only the assigned source identity. IPv6, VLANs, unknown L2,
// fragmented IPv4 and unsolicited IP/MAC identities never enter the stack.
func (n *Network) Input(b []byte) {
	n.stats.frames.Add(1)
	if len(b) > n.options.settings.MTU+14 {
		n.stats.oversized.Add(1)
		return
	}
	if len(b) < 14 || string(b[6:12]) != string(n.mac) {
		n.stats.macDenied.Add(1)
		return
	}
	typ := binary.BigEndian.Uint16(b[12:14])
	switch typ {
	case 0x0806:
		n.stats.arp.Add(1)
		if string(b[:6]) != gatewayMAC && string(b[:6]) != "\xff\xff\xff\xff\xff\xff" {
			return
		}
		if len(b) < 42 || binary.BigEndian.Uint16(b[14:16]) != 1 || binary.BigEndian.Uint16(b[16:18]) != 0x800 || b[18] != 6 || b[19] != 4 || string(b[22:28]) != string(n.mac) {
			return
		}
		if binary.BigEndian.Uint16(b[20:22]) != 1 || binary.BigEndian.Uint32(b[38:42]) != 0xc0000201 {
			return
		}
		source := binary.BigEndian.Uint32(b[28:32])
		if source != 0 && source != 0xc0000202 {
			return
		}
	case 0x0800:
		n.stats.ipv4.Add(1)
		if len(b) < 34 || b[14]>>4 != 4 || b[14]&15 < 5 || int(binary.BigEndian.Uint16(b[16:18])) > len(b)-14 || binary.BigEndian.Uint16(b[20:22])&0x3fff != 0 {
			return
		}
		if n.dhcp(b) {
			return
		}
		// ICMP needs a separate admitted echo/error translator, with identifier
		// ownership and validation of quoted packets. Do not enable it by simply
		// passing ICMP frames through to a host raw socket.
		if b[23] != 6 && b[23] != 17 {
			n.stats.protocolDenied.Add(1)
			return
		}
		if string(b[:6]) != gatewayMAC {
			return
		}
		if binary.BigEndian.Uint32(b[26:30]) != 0xc0000202 {
			n.stats.sourceDenied.Add(1)
			return
		}
	case 0x86dd:
		// Deliberate family gate. IPv6 support belongs in its own handler with
		// scoped host/LAN route admission and NDP/RA control; it can coexist
		// with DHCPv4/ARP without changing this private Ethernet attachment.
		n.stats.ipv6.Add(1)
		return
	default:
		return
	}
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b...))})
	n.link.InjectInbound(0, p)
	p.DecRef()
}
func (n *Network) Output(ctx context.Context) []byte { return n.wire.read(ctx) }

func (n *Network) Close() {
	n.once.Do(func() {
		n.mu.Lock()
		n.closed = true
		n.cancel()
		for c := range n.cacheFlows {
			_ = c.Close()
		}
		for c := range n.flows {
			_ = c.Close()
		}
		n.mu.Unlock()
		n.s.Close()
		n.link.Close()
		n.wg.Wait()
		n.s.Wait()
	})
}
