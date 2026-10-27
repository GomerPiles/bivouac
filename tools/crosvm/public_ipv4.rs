// Copyright (c) 2026 GomerPiles. SPDX-License-Identifier: MIT
//
// Experimental packet admission BEFORE libslirp creates host sockets.
// A fixed public IPv4 policy cannot be implemented with a VM-port VFP rule
// here: Windows Slirp uses sockets in the device process, not a VM NIC.
// The manager supplies all connected host IPv4 prefixes. Interface changes
// require retiring the guest; this snapshot is not an atomic dynamic policy.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
struct Prefix(u32, u8);
impl Prefix {
    fn parse(text: &str) -> Result<Self, &'static str> {
        let (address, bits) = text.split_once('/').ok_or("prefix lacks a mask")?;
        let address = address
            .parse::<Ipv4Addr>()
            .map_err(|_| "invalid IPv4 prefix")?;
        let bits = bits.parse::<u8>().map_err(|_| "invalid IPv4 mask")?;
        if bits == 0 || bits > 32 {
            return Err("invalid IPv4 mask");
        }
        Ok(Self(u32::from(address) & (u32::MAX << (32 - bits)), bits))
    }
    fn contains(self, address: Ipv4Addr) -> bool {
        u32::from(address) & (u32::MAX << (32 - self.1)) == self.0
    }
}

struct Packet<'a> {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    fragmented: bool,
    payload: &'a [u8],
}
fn ipv4(frame: &[u8]) -> Option<Packet<'_>> {
    if frame.len() < 34 || frame[12..14] != [8, 0] || frame[14] != 0x45 {
        return None;
    }
    let length = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    if length < 20 || 14 + length > frame.len() {
        return None;
    }
    Some(Packet {
        source: Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29]),
        destination: Ipv4Addr::new(frame[30], frame[31], frame[32], frame[33]),
        protocol: frame[23],
        fragmented: u16::from_be_bytes([frame[20], frame[21]]) & 0x3fff != 0,
        payload: &frame[34..14 + length],
    })
}
struct Tcp {
    source: u16,
    destination: u16,
    flags: u8,
    acknowledgement: u32,
    sequence: u32,
}
fn tcp(packet: &Packet<'_>) -> Option<Tcp> {
    let p = packet.payload;
    if packet.protocol != 6 || packet.fragmented || p.len() < 20 {
        return None;
    }
    let header = usize::from(p[12] >> 4) * 4;
    if header < 20 || header > p.len() {
        return None;
    }
    Some(Tcp {
        source: u16::from_be_bytes([p[0], p[1]]),
        destination: u16::from_be_bytes([p[2], p[3]]),
        flags: p[13],
        sequence: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
        acknowledgement: u32::from_be_bytes([p[8], p[9], p[10], p[11]]),
    })
}
struct ManagementFlow {
    host: Ipv4Addr,
    port: u16,
    initial_sequence: u32,
    established: bool,
    closing: bool,
    expires: Instant,
}
pub struct PublicIpv4 {
    denied: Vec<Prefix>,
    host_alias: Ipv4Addr,
    guest: Ipv4Addr,
    management: Vec<ManagementFlow>,
}
/// The only value that disables filtering, for positive-control tests of this
/// same binary. Bivouac never supplies it; an absent policy fails closed.
pub const UNFILTERED_CONTROL: &str = "unfiltered-positive-control";

impl PublicIpv4 {
    /// Panics, refusing to create the Slirp network, unless the environment
    /// selects the filter with a valid inventory or the explicit control mode.
    pub fn from_environment(host_alias: Ipv4Addr, guest: Ipv4Addr) -> Option<Self> {
        let policy = std::env::var("BIVOUAC_SLIRP_POLICY").ok();
        let hosts = std::env::var("BIVOUAC_SLIRP_HOST_PREFIXES").ok();
        Self::from_values(host_alias, guest, policy.as_deref(), hosts.as_deref())
            .unwrap_or_else(|error| panic!("Bivouac network policy: {error}"))
    }
    fn from_values(
        host_alias: Ipv4Addr,
        guest: Ipv4Addr,
        policy: Option<&str>,
        hosts: Option<&str>,
    ) -> Result<Option<Self>, &'static str> {
        match policy {
            Some("public-ipv4-v1") => {
                let hosts = hosts.ok_or("mandatory host-prefix inventory is missing")?;
                Self::new(host_alias, guest, hosts).map(Some)
            }
            Some(UNFILTERED_CONTROL) => Ok(None),
            Some(_) => Err("invalid mandatory policy"),
            None => Err("BIVOUAC_SLIRP_POLICY is missing; refusing unfiltered networking"),
        }
    }
    pub fn new(host_alias: Ipv4Addr, guest: Ipv4Addr, hosts: &str) -> Result<Self, &'static str> {
        const RESERVED: &str = "0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.168.0.0/16,192.88.99.0/24,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,240.0.0.0/4";
        if hosts.is_empty() || hosts.split(',').count() > 128 {
            return Err("invalid host inventory bound");
        }
        let mut denied = Vec::new();
        for prefix in RESERVED.split(',').chain(hosts.split(',')) {
            denied.push(Prefix::parse(prefix)?);
        }
        Ok(Self {
            denied,
            host_alias,
            guest,
            management: Vec::new(),
        })
    }
    fn expire(&mut self) {
        self.management.retain(|flow| flow.expires > Instant::now());
    }

    // Only Slirp's outgoing, host-originated SSH SYN can authorize its reverse
    // traffic. Merely using source port 22 never grants access to the gateway.
    pub fn observe_host_packet(&mut self, frame: &[u8]) {
        let Some(packet) = ipv4(frame) else {
            return;
        };
        let Some(tcp) = tcp(&packet) else {
            return;
        };
        if packet.destination != self.guest
            || tcp.destination != 22
            || !(packet.source == self.host_alias || packet.source == Ipv4Addr::LOCALHOST)
        {
            return;
        }
        self.expire();
        if tcp.flags & 0x17 == 0x02 {
            self.management
                .retain(|flow| !(flow.host == packet.source && flow.port == tcp.source));
            if self.management.len() < 64 {
                self.management.push(ManagementFlow {
                    host: packet.source,
                    port: tcp.source,
                    initial_sequence: tcp.sequence,
                    established: false,
                    closing: false,
                    expires: Instant::now() + Duration::from_secs(120),
                });
            }
        } else if tcp.flags & 0x05 != 0 {
            if let Some(flow) = self
                .management
                .iter_mut()
                .find(|flow| flow.host == packet.source && flow.port == tcp.source)
            {
                flow.closing = true;
                flow.expires = Instant::now() + Duration::from_secs(5);
            }
        }
    }
    fn management_reply(&mut self, packet: &Packet<'_>) -> bool {
        let Some(tcp) = tcp(packet) else {
            return false;
        };
        if packet.source != self.guest || tcp.source != 22 {
            return false;
        }
        self.expire();
        let Some(flow) = self
            .management
            .iter_mut()
            .find(|flow| flow.host == packet.destination && flow.port == tcp.destination)
        else {
            return false;
        };
        if tcp.flags & 0x02 != 0 {
            if tcp.flags & 0x17 != 0x12
                || tcp.acknowledgement != flow.initial_sequence.wrapping_add(1)
            {
                return false;
            }
            flow.established = true;
        } else if !flow.established || tcp.flags & 0x10 == 0 {
            return false;
        }
        flow.closing |= tcp.flags & 0x05 != 0;
        flow.expires = Instant::now() + Duration::from_secs(if flow.closing { 5 } else { 120 });
        true
    }
    fn dhcp(&self, packet: &Packet<'_>) -> bool {
        let p = packet.payload;
        packet.protocol == 17
            && !packet.fragmented
            && p.len() >= 248
            && (packet.source == Ipv4Addr::UNSPECIFIED || packet.source == self.guest)
            && (packet.destination == Ipv4Addr::BROADCAST || packet.destination == self.host_alias)
            && p[0..4] == [0, 68, 0, 67]
            && p[8..12] == [1, 1, 6, 0]
            && p[244..248] == [99, 130, 83, 99]
    }
    pub fn allow_guest_packet(&mut self, frame: &[u8]) -> bool {
        // ARP is handled inside Slirp and never becomes a host socket.
        if frame.len() >= 42 && frame[12..14] == [8, 6] {
            return frame[14..20] == [0, 1, 8, 0, 6, 4]
                && matches!(frame[21], 1 | 2)
                && frame[20] == 0;
        }
        let Some(packet) = ipv4(frame) else {
            return false;
        };
        if self.dhcp(&packet) {
            return true;
        }
        if packet.source != self.guest {
            return false;
        }
        if self
            .denied
            .iter()
            .any(|prefix| prefix.contains(packet.destination))
        {
            return self.management_reply(&packet);
        }
        matches!(packet.protocol, 1 | 6 | 17)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> PublicIpv4 {
        PublicIpv4::new(
            Ipv4Addr::new(10, 0, 2, 2),
            Ipv4Addr::new(10, 0, 2, 15),
            "8.8.8.10/24",
        )
        .unwrap()
    }
    fn frame(source: [u8; 4], destination: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0; 34 + payload.len()];
        p[12..14].copy_from_slice(&[8, 0]);
        p[14] = 0x45;
        p[16..18].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        p[23] = protocol;
        p[26..30].copy_from_slice(&source);
        p[30..34].copy_from_slice(&destination);
        p[34..].copy_from_slice(payload);
        p
    }
    fn tcp_frame(
        source: [u8; 4],
        destination: [u8; 4],
        src: u16,
        dst: u16,
        flags: u8,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        let mut p = vec![0; 20];
        p[0..2].copy_from_slice(&src.to_be_bytes());
        p[2..4].copy_from_slice(&dst.to_be_bytes());
        p[4..8].copy_from_slice(&seq.to_be_bytes());
        p[8..12].copy_from_slice(&ack.to_be_bytes());
        p[12] = 0x50;
        p[13] = flags;
        frame(source, destination, 6, &p)
    }
    #[test]
    fn private_reserved_and_public_host_addresses_are_denied() {
        let mut p = policy();
        for destination in [
            [127, 0, 0, 1],
            [10, 0, 2, 2],
            [192, 168, 1, 1],
            [192, 88, 99, 1],
            [169, 254, 169, 254],
            [100, 64, 1, 1],
            [8, 8, 8, 11],
            [240, 0, 0, 1],
        ] {
            for protocol in [1, 6, 17] {
                assert!(!p.allow_guest_packet(&frame(
                    [10, 0, 2, 15],
                    destination,
                    protocol,
                    &[0; 20]
                )));
            }
        }
        assert!(p.allow_guest_packet(&frame([10, 0, 2, 15], [1, 1, 1, 1], 17, &[0; 8])));
    }
    #[test]
    fn ssh_source_port_is_not_a_gateway_exception() {
        let mut p = policy();
        assert!(!p.allow_guest_packet(&tcp_frame([10, 0, 2, 15], [10, 0, 2, 2], 22, 443, 2, 1, 0)));
        assert!(!p.allow_guest_packet(&tcp_frame(
            [10, 0, 2, 15],
            [10, 0, 2, 2],
            22,
            443,
            0x12,
            1,
            1
        )));
    }
    #[test]
    fn only_observed_ssh_reply_tuple_and_handshake_are_allowed() {
        let mut p = policy();
        p.observe_host_packet(&tcp_frame(
            [10, 0, 2, 2],
            [10, 0, 2, 15],
            40000,
            22,
            2,
            42,
            0,
        ));
        assert!(!p.allow_guest_packet(&tcp_frame(
            [10, 0, 2, 15],
            [10, 0, 2, 2],
            22,
            40000,
            0x10,
            1,
            43
        )));
        assert!(!p.allow_guest_packet(&tcp_frame(
            [10, 0, 2, 15],
            [10, 0, 2, 2],
            22,
            40000,
            0x12,
            1,
            44
        )));
        assert!(!p.allow_guest_packet(&tcp_frame(
            [10, 0, 2, 15],
            [10, 0, 2, 2],
            22,
            40001,
            0x12,
            1,
            43
        )));
        assert!(p.allow_guest_packet(&tcp_frame(
            [10, 0, 2, 15],
            [10, 0, 2, 2],
            22,
            40000,
            0x12,
            1,
            43
        )));
        assert!(p.allow_guest_packet(&tcp_frame(
            [10, 0, 2, 15],
            [10, 0, 2, 2],
            22,
            40000,
            0x10,
            2,
            43
        )));
        assert!(!p.allow_guest_packet(&tcp_frame(
            [10, 0, 2, 15],
            [10, 0, 2, 2],
            22,
            40000,
            2,
            2,
            0
        )));
    }
    #[test]
    fn virtual_dns_ipv6_vlan_options_and_short_frames_are_denied() {
        let mut p = policy();
        assert!(!p.allow_guest_packet(&frame([10, 0, 2, 15], [10, 0, 2, 3], 17, &[0; 8])));
        let mut f = frame([10, 0, 2, 15], [1, 1, 1, 1], 17, &[0; 8]);
        f[12..14].copy_from_slice(&[0x86, 0xdd]);
        assert!(!p.allow_guest_packet(&f));
        f[12..14].copy_from_slice(&[0x81, 0]);
        assert!(!p.allow_guest_packet(&f));
        f[12..14].copy_from_slice(&[8, 0]);
        f[14] = 0x46;
        assert!(!p.allow_guest_packet(&f));
        for length in 0..34 {
            assert!(!p.allow_guest_packet(&f[..length]));
        }
    }
    #[test]
    fn dhcp_exception_does_not_allow_other_private_udp() {
        let mut p = policy();
        let mut payload = vec![0; 248];
        payload[0..4].copy_from_slice(&[0, 68, 0, 67]);
        payload[8..12].copy_from_slice(&[1, 1, 6, 0]);
        payload[244..248].copy_from_slice(&[99, 130, 83, 99]);
        assert!(p.allow_guest_packet(&frame([0, 0, 0, 0], [255, 255, 255, 255], 17, &payload)));
        assert!(!p.allow_guest_packet(&frame([0, 0, 0, 0], [192, 168, 1, 1], 17, &payload)));
        payload[3] = 53;
        assert!(!p.allow_guest_packet(&frame([0, 0, 0, 0], [10, 0, 2, 2], 17, &payload)));
    }
    #[test]
    fn fragmented_management_and_expired_flows_are_denied() {
        let mut p = policy();
        p.observe_host_packet(&tcp_frame(
            [10, 0, 2, 2],
            [10, 0, 2, 15],
            40000,
            22,
            2,
            42,
            0,
        ));
        let mut f = tcp_frame([10, 0, 2, 15], [10, 0, 2, 2], 22, 40000, 0x12, 1, 43);
        f[20] = 0x20;
        assert!(!p.allow_guest_packet(&f));
        p.management[0].expires = Instant::now();
        f[20] = 0;
        assert!(!p.allow_guest_packet(&f));
    }
    #[test]
    fn closing_ssh_ack_does_not_keep_a_dead_tuple_for_two_minutes() {
        let mut p = policy();
        p.observe_host_packet(&tcp_frame(
            [10, 0, 2, 2],
            [10, 0, 2, 15],
            40000,
            22,
            2,
            42,
            0,
        ));
        assert!(p.allow_guest_packet(&tcp_frame(
            [10, 0, 2, 15],
            [10, 0, 2, 2],
            22,
            40000,
            0x12,
            1,
            43
        )));
        p.observe_host_packet(&tcp_frame(
            [10, 0, 2, 2],
            [10, 0, 2, 15],
            40000,
            22,
            0x11,
            43,
            2,
        ));
        assert!(p.allow_guest_packet(&tcp_frame(
            [10, 0, 2, 15],
            [10, 0, 2, 2],
            22,
            40000,
            0x10,
            2,
            44
        )));
        assert!(p.management[0].expires.duration_since(Instant::now()) <= Duration::from_secs(5));
    }
    #[test]
    fn absent_or_invalid_policy_fails_closed() {
        let (host, guest) = (Ipv4Addr::new(10, 0, 2, 2), Ipv4Addr::new(10, 0, 2, 15));
        for (policy, hosts) in [
            (None, None),
            (None, Some("8.8.8.10/24")),
            (Some(""), Some("8.8.8.10/24")),
            (Some("public-ipv4-v2"), Some("8.8.8.10/24")),
            (Some("public-ipv4-v1"), None),
            (Some("public-ipv4-v1"), Some("")),
        ] {
            assert!(PublicIpv4::from_values(host, guest, policy, hosts).is_err());
        }
        let filtered =
            PublicIpv4::from_values(host, guest, Some("public-ipv4-v1"), Some("8.8.8.10/24"));
        assert!(matches!(filtered, Ok(Some(_))));
        let control = PublicIpv4::from_values(host, guest, Some(UNFILTERED_CONTROL), None);
        assert!(matches!(control, Ok(None)));
    }
    #[test]
    fn invalid_inventory_fails_closed() {
        for hosts in ["", "0.0.0.0/0", "::1/128", "1.1.1.1/33", "garbage"] {
            assert!(
                PublicIpv4::new(Ipv4Addr::LOCALHOST, Ipv4Addr::new(10, 0, 2, 15), hosts).is_err()
            );
        }
    }
}
