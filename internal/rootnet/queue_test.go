package rootnet

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func queueFrame(link *packetLink, data []byte) (int, tcpip.Error) {
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
	defer packet.DecRef()
	var list stack.PacketBufferList
	list.PushBack(packet)
	return link.WritePackets(list)
}

func TestSaturatedPacketQueueReturnsWithoutHoldingStackProgress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint := channel.New(1, 1514, tcpip.LinkAddress(gatewayMAC))
	defer endpoint.Close()
	link := newPacketLink(ctx, endpoint, 2, 1)
	for range 2 {
		if count, err := queueFrame(link, []byte("opaque data")); err != nil || count != 1 {
			t.Fatal("initial packet admission failed")
		}
	}
	done := make(chan struct{})
	var count int
	var err tcpip.Error
	go func() { defer close(done); count, err = queueFrame(link, []byte("burst")) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("full output queue blocked protocol/ACK progress")
	}
	if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok || count != 0 || link.dataDropped.Load()+link.controlDropped.Load() != 1 {
		t.Fatal("queue loss was not bounded and explicit")
	}
	// A pure TCP ACK retains admission capacity without reordering earlier data.
	ack := make([]byte, 54)
	binary.BigEndian.PutUint16(ack[12:], 0x800)
	ack[14] = 0x45
	binary.BigEndian.PutUint16(ack[16:], 40)
	ack[23] = 6
	ack[46] = 0x50
	ack[47] = 0x10
	if count, err := queueFrame(link, ack); err != nil || count != 1 {
		t.Fatal("data burst consumed ACK capacity")
	}
	for range 2 {
		if string(link.read(ctx)) != "opaque data" {
			t.Fatal("control reordered earlier data")
		}
	}
	if got := link.read(ctx); len(got) != len(ack) || got[47] != 0x10 {
		t.Fatal("ACK did not retain capacity during a data burst")
	}
	cancel()
	if count, err := queueFrame(link, ack); err == nil || count != 0 {
		t.Fatal("closed wire admitted more packets")
	}
	if link.read(context.Background()) != nil {
		t.Fatal("closed wire continued draining queued packets")
	}
}

func TestFullDataQueueKeepsDNSAndLinkControlCapacity(t *testing.T) {
	for _, kind := range []string{"arp", "dns", "dhcp"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			endpoint := channel.New(1, 1514, tcpip.LinkAddress(gatewayMAC))
			defer endpoint.Close()
			link := newPacketLink(ctx, endpoint, 1, 1)
			_, _ = queueFrame(link, []byte("full data queue"))
			frame := make([]byte, 42)
			if kind == "arp" {
				binary.BigEndian.PutUint16(frame[12:], 0x806)
				binary.BigEndian.PutUint16(frame[14:], 1)
				binary.BigEndian.PutUint16(frame[16:], 0x800)
				frame[18] = 6
				frame[19] = 4
			} else {
				binary.BigEndian.PutUint16(frame[12:], 0x800)
				frame[14] = 0x45
				binary.BigEndian.PutUint16(frame[16:], 28)
				frame[23] = 17
				port := uint16(53)
				if kind == "dhcp" {
					port = 67
				}
				binary.BigEndian.PutUint16(frame[34:], port)
			}
			if n, err := queueFrame(link, frame); n != 1 || err != nil {
				t.Fatal("data burst consumed link/DNS control capacity")
			}
			if string(link.read(ctx)) != "full data queue" {
				t.Fatal("control reordered queued data")
			}
			if got := link.read(ctx); len(got) != len(frame) {
				t.Fatal("control frame did not retain bounded progress")
			}
		})
	}
}

func TestControlFloodCannotStarveQueuedData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint := channel.New(1, 1514, tcpip.LinkAddress(gatewayMAC))
	defer endpoint.Close()
	link := newPacketLink(ctx, endpoint, 1, 16)
	_, _ = queueFrame(link, []byte("ordinary data"))
	ack := make([]byte, 54)
	binary.BigEndian.PutUint16(ack[12:], 0x800)
	ack[14] = 0x45
	binary.BigEndian.PutUint16(ack[16:], 40)
	ack[23] = 6
	ack[46] = 0x50
	ack[47] = 0x10
	for range 16 {
		if n, err := queueFrame(link, ack); n != 1 || err != nil {
			t.Fatal("control fixture exceeded its queue")
		}
	}
	if string(link.read(ctx)) != "ordinary data" {
		t.Fatal("control flood reordered or starved earlier data")
	}
	for range 16 {
		if len(link.read(ctx)) != len(ack) {
			t.Fatal("control reserve did not make progress")
		}
	}

}
func TestRejectedPacketBatchAccountsUnacceptedTail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint := channel.New(1, 1514, tcpip.LinkAddress(gatewayMAC))
	defer endpoint.Close()
	link := newPacketLink(ctx, endpoint, 1, 1)
	_, _ = queueFrame(link, []byte("full"))
	ack := make([]byte, 54)
	binary.BigEndian.PutUint16(ack[12:], 0x800)
	ack[14] = 0x45
	binary.BigEndian.PutUint16(ack[16:], 40)
	ack[23] = 6
	ack[46] = 0x50
	ack[47] = 0x10
	var packets stack.PacketBufferList
	for _, data := range [][]byte{[]byte("data"), ack} {
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		defer packet.DecRef()
		packets.PushBack(packet)
	}
	if n, err := link.WritePackets(packets); n != 0 || err == nil {
		t.Fatal("full queue did not reject its packet batch")
	}
	if link.dataDropped.Load() != 1 || link.controlDropped.Load() != 1 {
		t.Fatal("unaccepted batch tail was omitted from loss counters")
	}
	if n, err := queueFrame(link, ack); n != 1 || err != nil {
		t.Fatal("a rejected data batch consumed reserved control capacity")
	}
}
func FuzzControlFrameBounds(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 14))
	f.Add(make([]byte, 54))
	seed := make([]byte, 54)
	binary.BigEndian.PutUint16(seed[12:], 0x800)
	seed[14] = 0x45
	binary.BigEndian.PutUint16(seed[16:], 40)
	seed[23] = 6
	seed[46] = 0x50
	seed[47] = 0x10
	f.Add(seed)
	f.Fuzz(func(t *testing.T, frame []byte) { _ = controlFrame(frame) })
}
