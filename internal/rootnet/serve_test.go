package rootnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestAttachmentLossCancelsNetworkAndJoinsWorkers(t *testing.T) {
	n, err := newNetwork(context.Background(), testMAC, options{
		allow: func(netip.Addr) bool { return true },
		dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("fixture does not open host sockets")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	link, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	done := make(chan error, 1)
	go func() { done <- n.Serve(link) }()
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || n.ctx.Err() == nil {
			t.Fatal("lost attachment did not terminate the network")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("network workers survived attachment loss")
	}
	// Close must join the stack as well as Serve's two link workers.
	closed := make(chan struct{})
	go func() { n.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("network close did not join its workers")
	}
}

func TestServeCountsOversizedFramesSeparately(t *testing.T) {
	n, err := newNetwork(context.Background(), testMAC, options{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	link, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	done := make(chan error, 1)
	go func() { done <- n.Serve(link) }()
	if _, err := peer.Write(make([]byte, n.options.settings.MTU+15)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for n.Stats().Oversized == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stats := n.Stats()
	if stats.Oversized != 1 || stats.MACDenied != 0 || stats.Frames != 1 {
		t.Fatal("attachment oversize bypassed dedicated counter")
	}
	_ = peer.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed attachment returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("attachment did not join")
	}
}
