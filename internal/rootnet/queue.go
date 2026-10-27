package rootnet

import (
	"context"
	"encoding/binary"
	"sync/atomic"

	"github.com/GomerPiles/bivouac/internal/cachelink"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const dataQueueFrames = 4096
const controlQueueFrames = 256

// packetLink never waits while netstack may hold protocol/NIC locks. Blocking
// here can prevent processing guest ACKs while the VZ attachment is congested.
// The FIFO and both admission budgets are bounded; loss is explicit and TCP
// can recover. Link control, DNS and payload-free TCP control retain capacity
// during a data burst without reordering already accepted segments.
type queuedFrame struct {
	data    []byte
	control bool
}
type packetLink struct {
	*channel.Endpoint
	ctx                         context.Context
	frames                      chan queuedFrame
	data, control               chan struct{}
	dataDropped, controlDropped atomic.Uint64
	dataBytes, controlBytes     atomic.Int64
	dataLimit, controlLimit     int64
}

func newPacketLink(ctx context.Context, endpoint *channel.Endpoint, data, control int) *packetLink {
	return &packetLink{Endpoint: endpoint, dataLimit: int64(data) * 1514, controlLimit: int64(control) * 1514, ctx: ctx, frames: make(chan queuedFrame, data+control), data: make(chan struct{}, data), control: make(chan struct{}, control)}
}
func (l *packetLink) enqueue(data []byte) bool {
	if l.ctx.Err() != nil {
		return false
	}
	control := controlFrame(data)
	slots := l.data
	if control {
		slots = l.control
	}
	used, limit := &l.dataBytes, l.dataLimit
	if control {
		used, limit = &l.controlBytes, l.controlLimit
	}
	reserved := false
	for before := used.Load(); int64(len(data)) <= limit-before; before = used.Load() {
		if used.CompareAndSwap(before, before+int64(len(data))) {
			reserved = true
			break
		}
	}
	if !reserved {
		if control {
			l.controlDropped.Add(1)
		} else {
			l.dataDropped.Add(1)
		}
		return false
	}
	select {
	case slots <- struct{}{}:
	default:
		used.Add(-int64(len(data)))
		if control {
			l.controlDropped.Add(1)
		} else {
			l.dataDropped.Add(1)
		}
		return false
	}
	// A slot reserves space in the combined FIFO. Keep the send nonblocking
	// even if that invariant changes, because callers may hold protocol locks.
	select {
	case l.frames <- queuedFrame{data: data, control: control}:
		return true
	default:
		<-slots
		used.Add(-int64(len(data)))
		if control {
			l.controlDropped.Add(1)
		} else {
			l.dataDropped.Add(1)
		}
		return false
	}
}
func (l *packetLink) WritePackets(packets stack.PacketBufferList) (int, tcpip.Error) {
	count := 0
	batch := packets.AsSlice()
	for index, packet := range batch {
		if l.ctx.Err() != nil {
			return count, &tcpip.ErrClosedForSend{}
		}
		view := packet.ToView()
		data := append([]byte(nil), view.AsSlice()...)
		view.Release()
		if !l.enqueue(data) {
			// WritePackets returns an accepted prefix. Account the remaining batch
			// as unaccepted too; a later control frame is retried by its caller.
			for _, pending := range batch[index+1:] {
				view := pending.ToView()
				control := controlFrame(view.AsSlice())
				view.Release()
				if control {
					l.controlDropped.Add(1)
				} else {
					l.dataDropped.Add(1)
				}
			}
			return count, &tcpip.ErrNoBufferSpace{}
		}
		count++
	}
	return count, nil
}

// One physical writer drains a bounded FIFO. Separate admission reserves keep
// data bursts from consuming control capacity without reordering TCP segments.
// FIFO also gives both classes bounded progress under a sustained flood.
func (l *packetLink) read(ctx context.Context) []byte {
	if ctx.Err() != nil || l.ctx.Err() != nil {
		return nil
	}
	select {
	case frame := <-l.frames:
		if frame.control {
			<-l.control
			l.controlBytes.Add(-int64(len(frame.data)))
		} else {
			<-l.data
			l.dataBytes.Add(-int64(len(frame.data)))
		}
		return frame.data
	case <-ctx.Done():
		return nil
	case <-l.ctx.Done():
		return nil
	}
}

// Only trusted, stack-produced outbound headers are classified. Unknown or
// malformed frames use the ordinary data budget; this never admits traffic.
func controlFrame(frame []byte) bool {
	if len(frame) < 14 {
		return false
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0806:
		return len(frame) >= 42 && binary.BigEndian.Uint16(frame[14:16]) == 1 && binary.BigEndian.Uint16(frame[16:18]) == 0x800 && frame[18] == 6 && frame[19] == 4
	case 0x0800:
		if len(frame) < 34 || frame[14]>>4 != 4 {
			return false
		}
		offset := 14 + int(frame[14]&15)*4
		total := 14 + int(binary.BigEndian.Uint16(frame[16:18]))
		if offset < 34 || total > len(frame) || total < offset || binary.BigEndian.Uint16(frame[20:22])&0x3fff != 0 {
			return false
		}
		switch frame[23] {
		case 17:
			if total < offset+8 {
				return false
			}
			source := binary.BigEndian.Uint16(frame[offset : offset+2])
			return source == 53 || source == 67
		case 6:
			if total < offset+20 {
				return false
			}
			end := offset + int(frame[offset+12]>>4)*4
			if end < offset+20 || end > total {
				return false
			}
			source := binary.BigEndian.Uint16(frame[offset : offset+2])
			virtualService := binary.BigEndian.Uint32(frame[26:30]) == 0xc0000201 && (source == 53 || source == cachelink.RevocationPort)
			return end == total || virtualService
		}
	}
	return false
}
