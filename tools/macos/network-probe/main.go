//go:build darwin

// network-probe is a disposable-guest lab tool. It refuses to run unless guest
// root and the private rootless test lease are present. No host BPF is opened.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/GomerPiles/bivouac/internal/rootnet"
	"golang.org/x/sys/unix"
)

func sum(b []byte) uint16 {
	var s uint32
	for len(b) > 1 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		s += uint32(b[0]) << 8
	}
	for s>>16 != 0 {
		s = s&65535 + s>>16
	}
	return ^uint16(s)
}
func ipv4(mac net.HardwareAddr, protocol byte, payload []byte) []byte {
	b := make([]byte, 34+len(payload))
	copy(b[:6], []byte{2, 0, 0, 0, 0, 1})
	copy(b[6:12], mac)
	binary.BigEndian.PutUint16(b[12:], 0x800)
	ip := b[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, protocol
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(payload))) //nolint:gosec // Only fixed 8/16-byte lab payloads call this helper.
	copy(ip[12:], net.ParseIP(rootnet.Guest).To4())
	copy(ip[16:], net.ParseIP(rootnet.Gateway).To4())
	binary.BigEndian.PutUint16(ip[10:], sum(ip))
	copy(b[34:], payload)
	return b
}
func run() error {
	if os.Geteuid() != 0 {
		return errors.New("disposable guest root required")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return errors.New("guest interface inventory unavailable")
	}
	var selected *net.Interface
	for index := range interfaces {
		addresses, err := interfaces[index].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addresses {
			ip, _, err := net.ParseCIDR(a.String())
			if err == nil && ip.String() == rootnet.Guest {
				selected = &interfaces[index]
				break
			}
		}
	}
	if selected == nil || len(selected.HardwareAddr) != 6 {
		return errors.New("rootless disposable-guest lease absent; BPF not opened")
	}
	fd := -1
	for index := 0; index < 32; index++ {
		candidate, err := unix.Open(fmt.Sprintf("/dev/bpf%d", index), unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			fd = candidate
			break
		}
		if !errors.Is(err, unix.EBUSY) {
			return errors.New("guest BPF unavailable")
		}
	}
	if fd < 0 {
		return errors.New("guest BPF devices busy")
	}
	defer func() { _ = unix.Close(fd) }()
	// x/net/bpf provides filter assembly, not the interface/header ioctls. These
	// stdlib wrappers supply the correctly sized BSD request without cgo.
	if syscall.SetBpfInterface(fd, selected.Name) != nil { //nolint:staticcheck // Typed BSD attachment ioctl; x/net/bpf only assembles filters.
		return errors.New("bind guest BPF")
	}
	if syscall.SetBpfHeadercmpl(fd, 1) != nil { //nolint:staticcheck // Typed BSD header ioctl; x/net/bpf only assembles filters.
		return errors.New("preserve guest test Ethernet header")
	}
	udp := make([]byte, 16)
	binary.BigEndian.PutUint16(udp, 41000)
	binary.BigEndian.PutUint16(udp[2:], 54545)
	binary.BigEndian.PutUint16(udp[4:], 16)
	copy(udp[8:], "lab-only")
	ordinary := ipv4(selected.HardwareAddr, 17, udp)
	spoofMAC := append([]byte(nil), ordinary...)
	spoofMAC[6] ^= 4
	spoofIP := append([]byte(nil), ordinary...)
	copy(spoofIP[26:], []byte{127, 0, 0, 1})
	spoofIP[24], spoofIP[25] = 0, 0
	binary.BigEndian.PutUint16(spoofIP[24:], sum(spoofIP[14:34]))
	icmp := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	binary.BigEndian.PutUint16(icmp[2:], sum(icmp))
	echo := ipv4(selected.HardwareAddr, 1, icmp)
	mdns := ipv4(selected.HardwareAddr, 17, udp)
	copy(mdns[:6], []byte{1, 0, 0x5e, 0, 0, 0xfb})
	copy(mdns[30:], []byte{224, 0, 0, 251})
	binary.BigEndian.PutUint16(mdns[36:], 5353)
	mdns[24], mdns[25] = 0, 0
	binary.BigEndian.PutUint16(mdns[24:], sum(mdns[14:34]))
	v6 := make([]byte, 14+40+24)
	copy(v6[:6], ordinary[:6])
	copy(v6[6:12], selected.HardwareAddr)
	binary.BigEndian.PutUint16(v6[12:], 0x86dd)
	h := v6[14:54]
	h[0], h[6], h[7] = 0x60, 58, 255
	binary.BigEndian.PutUint16(h[4:], 24)
	copy(h[8:], net.ParseIP("fe80::2").To16())
	copy(h[24:], net.ParseIP("fe80::1").To16())
	v6[54] = 135
	copy(v6[62:], net.ParseIP("fe80::1").To16())
	pseudo := make([]byte, 40+24)
	copy(pseudo, h[8:40])
	binary.BigEndian.PutUint32(pseudo[32:], 24)
	pseudo[39] = 58
	copy(pseudo[40:], v6[54:])
	binary.BigEndian.PutUint16(v6[56:], sum(pseudo))
	dns := append([]byte(nil), ordinary...)
	binary.BigEndian.PutUint16(dns[36:], 53)
	frames := [][]byte{ordinary, spoofMAC, spoofIP, echo, mdns, v6, dns}
	for _, frame := range frames {
		if count, err := unix.Write(fd, frame); err != nil || count != len(frame) {
			return errors.New("guest packet probe write failed")
		}
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Frames int `json:"frames_sent"`
	}{len(frames)})
}
func main() {
	operation := run
	if len(os.Args) == 2 && os.Args[1] == "--metal" {
		operation = metal
	}
	if err := operation(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
