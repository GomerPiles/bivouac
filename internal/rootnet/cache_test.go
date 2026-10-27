package rootnet

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cachelink"
	"github.com/GomerPiles/bivouac/internal/config"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestCacheEndpointIsExactAndIndependentOfPublicAdmission(t *testing.T) {
	var cacheDials, publicDials atomic.Int32
	n, err := newNetwork(context.Background(), testMAC, options{
		allow: func(netip.Addr) bool { return false },
		dial: func(context.Context, string, string) (net.Conn, error) {
			publicDials.Add(1)
			return nil, io.ErrClosedPipe
		},
		cacheDial: func(context.Context, cachelink.Kind) (net.Conn, error) {
			cacheDials.Add(1)
			a, b := net.Pipe()
			go func() { defer func() { _ = b.Close() }(); _, _ = io.CopyN(b, zeroReader{}, 2<<20) }()
			return a, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, ctx := guestStack(t, n)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			c, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: cachelink.Port}, ipv4.ProtocolNumber)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(time.Minute))
			count, err := io.Copy(io.Discard, c)
			if err == nil && count != 2<<20 {
				err = io.ErrUnexpectedEOF
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("transfer: %v stats=%+v", err, n.Stats())
		}
	}
	t.Logf("concurrent transfer stats: %+v", n.Stats())
	for _, target := range []struct {
		ip   [4]byte
		port uint16
	}{{[4]byte{192, 0, 2, 1}, 443}, {[4]byte{192, 0, 2, 2}, 7443}, {[4]byte{127, 0, 0, 1}, 7443}, {[4]byte{10, 0, 0, 1}, 7443}, {[4]byte{1, 1, 1, 1}, 443}} {
		c, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.ip), Port: target.port}, ipv4.ProtocolNumber)
		if err == nil {
			_ = c.Close()
			t.Fatal("non-capability destination admitted")
		}
	}
	if cacheDials.Load() != 16 || publicDials.Load() != 0 {
		t.Fatal("endpoint escaped its fixed capability")
	}
}

func TestRevocationCapacityIndependentOfFullPayloadFlows(t *testing.T) {
	n, err := newNetwork(context.Background(), testMAC, options{settings: config.VZNetwork{MaxFlows: 4}, allow: func(netip.Addr) bool { return false }, cacheDial: func(ctx context.Context, kind cachelink.Kind) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			defer func() { _ = b.Close() }()
			if kind == cachelink.Revocation {
				_, _ = io.WriteString(b, "signed public data")
			} else {
				_, _ = io.Copy(io.Discard, b)
			}
		}()
		return a, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, parent := guestStack(t, n)
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	for range 4 {
		c, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: cachelink.Port}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal("payload capacity unavailable")
		}
		defer func() { _ = c.Close() }()
	}
	c, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: cachelink.RevocationPort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal("payload saturation consumed revocation admission")
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	data, err := io.ReadAll(c)
	if err != nil || string(data) != "signed public data" {
		t.Fatal("revocation transport blocked behind payloads")
	}
}
