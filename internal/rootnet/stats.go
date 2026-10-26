package rootnet

import "sync/atomic"

type counters struct {
	flowLimit, admissionDenied, dialFailed, dnsRefused, dnsFailed                                                                            atomic.Uint64
	oversized, frames, macDenied, sourceDenied, protocolDenied, dnsInvalid, arp, ipv4, ipv6, dhcp, dhcpReply, ipChecksum, udpChecksum, bootp atomic.Uint64
}

// Snapshot is the fixed numeric report accepted from the sandboxed child.
// It cannot encode packet contents, strings, addresses or arbitrary log fields.
type Snapshot struct {
	ActivePublicTCP     uint64 `json:"active_public_tcp"`
	ActiveUDP           uint64 `json:"active_udp"`
	ActiveCache         uint64 `json:"active_cache"`
	Oversized           uint64 `json:"oversized"`
	FlowLimit           uint64 `json:"flow_limit"`
	AdmissionDenied     uint64 `json:"admission_denied"`
	DialFailed          uint64 `json:"dial_failed"`
	DNSRefused          uint64 `json:"dns_refused"`
	DNSFailed           uint64 `json:"dns_failed"`
	QueueDropped        uint64 `json:"queue_dropped"`
	QueueDataDropped    uint64 `json:"queue_data_dropped"`
	QueueControlDropped uint64 `json:"queue_control_dropped"`
	TCPRetransmits      uint64 `json:"tcp_retransmits"`
	TCPTimeouts         uint64 `json:"tcp_timeouts"`
	TCPSendErrors       uint64 `json:"tcp_send_errors"`
	Frames              uint64 `json:"frames"`
	MACDenied           uint64 `json:"mac_denied"`
	SourceDenied        uint64 `json:"source_denied"`
	ProtocolDenied      uint64 `json:"protocol_denied"`
	DNSInvalid          uint64 `json:"dns_invalid"`
	ARP                 uint64 `json:"arp"`
	IPv4                uint64 `json:"ipv4"`
	IPv6                uint64 `json:"ipv6"`
	DHCP                uint64 `json:"dhcp"`
	DHCPReply           uint64 `json:"dhcp_reply"`
	IPChecksum          uint64 `json:"dhcp_ip_checksum_denied"`
	UDPChecksum         uint64 `json:"dhcp_udp_checksum_denied"`
	BOOTP               uint64 `json:"dhcp_bootp_denied"`
}

func (n *Network) Stats() Snapshot {
	// Read all gauges under the slot-accounting lock, so their sum is a
	// consistent observation of general-pool occupancy, including pending dials.
	n.mu.Lock()
	publicTCP, udp, cache := n.activePublicTCP, n.activeUDP, n.activeCache
	n.mu.Unlock()
	tcp := n.s.Stats().TCP
	dataDrops, controlDrops := n.wire.dataDropped.Load(), n.wire.controlDropped.Load()
	return Snapshot{ActivePublicTCP: publicTCP, ActiveUDP: udp, ActiveCache: cache, Oversized: n.stats.oversized.Load(), FlowLimit: n.stats.flowLimit.Load(), AdmissionDenied: n.stats.admissionDenied.Load(), DialFailed: n.stats.dialFailed.Load(), DNSRefused: n.stats.dnsRefused.Load(), DNSFailed: n.stats.dnsFailed.Load(), QueueDropped: dataDrops + controlDrops, QueueDataDropped: dataDrops, QueueControlDropped: controlDrops, TCPRetransmits: tcp.Retransmits.Value(), TCPTimeouts: tcp.Timeouts.Value(), TCPSendErrors: tcp.SegmentSendErrors.Value(), Frames: n.stats.frames.Load(), MACDenied: n.stats.macDenied.Load(), SourceDenied: n.stats.sourceDenied.Load(), ProtocolDenied: n.stats.protocolDenied.Load(), DNSInvalid: n.stats.dnsInvalid.Load(), ARP: n.stats.arp.Load(), IPv4: n.stats.ipv4.Load(), IPv6: n.stats.ipv6.Load(), DHCP: n.stats.dhcp.Load(), DHCPReply: n.stats.dhcpReply.Load(), IPChecksum: n.stats.ipChecksum.Load(), UDPChecksum: n.stats.udpChecksum.Load(), BOOTP: n.stats.bootp.Load()}
}
