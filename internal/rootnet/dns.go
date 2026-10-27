package rootnet

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/GomerPiles/bivouac/internal/dnsproxy"
	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func (n *Network) dnsResponse(input []byte) []byte {
	q, query, err := dnsproxy.Query(input)
	if errors.Is(err, dnsproxy.BadVersion) {
		return dnsproxy.Failure(q, dns.RcodeBadVers)
	}
	if err != nil {
		n.stats.dnsInvalid.Add(1)
		return nil
	}
	if q.Question[0].Qtype == dns.TypeAAAA {
		return dnsproxy.Failure(q, dns.RcodeSuccess)
	}
	ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()
	raw, err := n.options.dnsExchange(ctx, query)
	if err != nil {
		n.stats.dnsFailed.Add(1)
		return dnsproxy.Failure(q, dns.RcodeServerFailure)
	}
	response, denied, err := dnsproxy.Filter(raw, q, n.options.allow)
	if err != nil {
		n.stats.dnsFailed.Add(1)
		return dnsproxy.Failure(q, dns.RcodeServerFailure)
	}
	if denied {
		n.stats.dnsRefused.Add(1)
	}
	var m dns.Msg
	if m.Unpack(response) == nil {
		if m.Rcode == dns.RcodeServerFailure {
			n.stats.dnsFailed.Add(1)
		}
		if m.Rcode == dns.RcodeRefused {
			n.stats.dnsRefused.Add(1)
		}
	}
	return response
}
func (n *Network) startDNS() error {
	address := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: 53}
	udp, err := gonet.DialUDP(n.s, &address, nil, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}
	tcp, err := gonet.ListenTCP(n.s, address, ipv4.ProtocolNumber)
	if err != nil {
		_ = udp.Close()
		return err
	}
	n.wg.Go(func() {
		defer func() { _ = udp.Close() }()
		stop := context.AfterFunc(n.ctx, func() { _ = udp.Close() })
		defer stop()
		b := make([]byte, 4097)
		for {
			count, peer, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			if !n.acquireDNS() {
				n.stats.dnsRefused.Add(1)
				continue
			}
			data := append([]byte(nil), b[:count]...)
			go func() {
				defer n.releaseDNS()
				if response := n.dnsResponse(data); response != nil {
					q, _, err := dnsproxy.Query(data)
					if err != nil && !errors.Is(err, dnsproxy.BadVersion) {
						return
					}
					response = dnsproxy.UDPResponse(response, q)

					_, _ = udp.WriteTo(response, peer)
				}
			}()
		}
	})
	n.wg.Go(func() {
		defer func() { _ = tcp.Close() }()
		stop := context.AfterFunc(n.ctx, func() { _ = tcp.Close() })
		defer stop()
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			if !n.acquireDNS() {
				n.stats.dnsRefused.Add(1)
				_ = c.Close()
				continue
			}
			go func() {
				defer n.releaseDNS()
				defer func() { _ = c.Close() }()
				stop := context.AfterFunc(n.ctx, func() { _ = c.Close() })
				defer stop()
				for range 16 {
					_ = c.SetDeadline(time.Now().Add(10 * time.Second))
					var h [2]byte
					if _, err := io.ReadFull(c, h[:]); err != nil {
						return
					}
					length := int(binary.BigEndian.Uint16(h[:]))
					if length > 4096 {
						return
					}
					b := make([]byte, length)
					if _, err := io.ReadFull(c, b); err != nil {
						return
					}
					response := n.dnsResponse(b)
					if response == nil || len(response) > 65535 {
						return
					}
					binary.BigEndian.PutUint16(h[:], uint16(len(response))) //nolint:gosec // Response is bounded to 65535 above.
					if _, err := c.Write(append(h[:], response...)); err != nil {
						return
					}
				}
			}()
		}
	})
	return nil
}
