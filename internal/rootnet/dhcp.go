package rootnet

import (
	"bytes"
	"encoding/binary"
)

func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) > 1 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&65535 + sum>>16
	}
	return ^uint16(sum)
}
func (n *Network) dhcp(frame []byte) bool {
	if len(frame) < 42 || frame[23] != 17 {
		return false
	}
	ihl := int(frame[14]&15) * 4
	if ihl < 20 || len(frame) < 14+ihl+8 {
		return false
	}
	udp := frame[14+ihl:]
	if binary.BigEndian.Uint16(udp) != 68 || binary.BigEndian.Uint16(udp[2:]) != 67 {
		return false
	}
	n.stats.dhcp.Add(1)
	if binary.BigEndian.Uint16(frame[20:22])&0x3fff != 0 || checksum(frame[14:14+ihl]) != 0 {
		n.stats.ipChecksum.Add(1)
		return true
	}
	length := int(binary.BigEndian.Uint16(udp[4:6]))
	if length < 248 || length > len(udp) {
		return true
	}
	total := int(binary.BigEndian.Uint16(frame[16:18]))
	source := binary.BigEndian.Uint32(frame[26:30])
	destination := binary.BigEndian.Uint32(frame[30:34])
	if total != ihl+length || source != 0 && source != 0xc0000202 || destination != 0xffffffff && destination != 0xc0000201 {
		return true
	}
	if binary.BigEndian.Uint16(udp[6:8]) != 0 {
		pseudo := make([]byte, 12+length)
		copy(pseudo, frame[26:34])
		pseudo[9] = 17
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(length)) //nolint:gosec // Length is decoded from a uint16 and bounded by one Ethernet frame.
		copy(pseudo[12:], udp[:length])
		if checksum(pseudo) != 0 {
			n.stats.udpChecksum.Add(1)
			return true
		}
	}
	boot := udp[8:length]
	if boot[0] != 1 || boot[1] != 1 || boot[2] != 6 || !bytes.Equal(boot[28:34], n.mac) || binary.BigEndian.Uint32(boot[236:240]) != 0x63825363 {
		n.stats.bootp.Add(1)
		return true
	}
	var kind byte
	wrongIP := false
	for pos := 240; pos < len(boot); {
		code := boot[pos]
		pos++
		if code == 255 {
			break
		}
		if code == 0 {
			continue
		}
		if pos >= len(boot) {
			return true
		}
		size := int(boot[pos])
		pos++
		if size > len(boot)-pos {
			return true
		}
		v := boot[pos : pos+size]
		pos += size
		switch code {
		case 53:
			if size != 1 {
				return true
			}
			kind = v[0]
		case 50:
			if size != 4 {
				return true
			}
			wrongIP = binary.BigEndian.Uint32(v) != 0xc0000202
		case 54:
			if size != 4 || binary.BigEndian.Uint32(v) != 0xc0000201 {
				return true
			}
		}
	}
	responseKind := byte(2)
	if kind == 3 {
		responseKind = 5
		if wrongIP {
			responseKind = 6
		}
	} else if kind != 1 {
		return true
	}
	b := make([]byte, 240)
	b[0], b[1], b[2] = 2, 1, 6
	copy(b[4:8], boot[4:8])
	binary.BigEndian.PutUint16(b[10:12], 0x8000)
	if responseKind != 6 {
		binary.BigEndian.PutUint32(b[16:20], 0xc0000202)
	}
	binary.BigEndian.PutUint32(b[20:24], 0xc0000201)
	copy(b[28:34], n.mac)
	binary.BigEndian.PutUint32(b[236:], 0x63825363)
	b = append(b, 53, 1, responseKind, 54, 4, 192, 0, 2, 1, 51, 4, 0, 0, 14, 16, 1, 4, 255, 255, 255, 0, 3, 4, 192, 0, 2, 1, 6, 4, 192, 0, 2, 1, 26, 2, byte(n.options.settings.MTU>>8), byte(n.options.settings.MTU&255), 255) //nolint:gosec // MTU is validated in 1500..65535.
	for len(b) < 300 {
		b = append(b, 0)
	}
	reply := make([]byte, 42+len(b))
	for i := 0; i < 6; i++ {
		reply[i] = 255
	}
	copy(reply[6:12], gatewayMAC)
	binary.BigEndian.PutUint16(reply[12:], 0x800)
	ip := reply[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:], uint16(28+len(b))) //nolint:gosec // Fixed DHCP reply, at most 328 bytes.
	binary.BigEndian.PutUint32(ip[12:], 0xc0000201)
	binary.BigEndian.PutUint32(ip[16:], 0xffffffff)
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))
	u := reply[34:]
	binary.BigEndian.PutUint16(u, 67)
	binary.BigEndian.PutUint16(u[2:], 68)
	binary.BigEndian.PutUint16(u[4:], uint16(len(u))) //nolint:gosec // Fixed DHCP reply, at most 308 bytes.
	copy(u[8:], b)
	if n.wire.enqueue(reply) {
		n.stats.dhcpReply.Add(1)
	}
	return true
}
