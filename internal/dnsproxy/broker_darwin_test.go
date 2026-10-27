package dnsproxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestBrokerConcurrentQueriesAndCancellation(t *testing.T) {
	started := make(chan struct{}, 2)
	var active atomic.Int32
	b, fd, err := NewBroker(func(ctx context.Context, raw []byte) ([]byte, error) {
		active.Add(1)
		defer active.Add(-1)
		var q dns.Msg
		if q.Unpack(raw) != nil {
			return nil, errors.New("invalid")
		}
		if q.Question[0].Qtype == dns.TypeTXT {
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		m := new(dns.Msg)
		m.SetReply(&q)
		return pack(t, m), nil
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	defer func() { _ = fd.Close() }()
	client, err := NewClient(fd, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := client.Resolve(ctx, pack(t, query(t, dns.TypeTXT))); result <- err }()
	<-started
	// A slow lookup must not serialize a second query.
	if _, err := client.Resolve(context.Background(), pack(t, query(t, dns.TypeMX))); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-result; err == nil {
		t.Fatal("cancelled query succeeded")
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("parent worker did not cancel")
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if _, err := client.Resolve(context.Background(), pack(t, query(t, dns.TypePTR))); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}
func TestBrokerRejectsMalformedQueriesWithoutResolving(t *testing.T) {
	var calls atomic.Int32
	b, fd, err := NewBroker(func(context.Context, []byte) ([]byte, error) { calls.Add(1); return nil, errors.New("unexpected") }, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	defer func() { _ = fd.Close() }()
	conn, err := net.FileConn(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	for _, raw := range [][]byte{{0}, make([]byte, 20)} {
		if _, err := conn.Write(message(queryOp, 7, raw)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil || n != 9 || buf[0] != failedOp {
			t.Fatal("malformed query did not fail")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("malformed child input reached resolver")
	}
}
func TestBrokerOwnBoundAndOwnerLoss(t *testing.T) {
	started := make(chan struct{})
	ended := make(chan struct{})
	b, fd, err := NewBroker(func(ctx context.Context, _ []byte) ([]byte, error) {
		close(started)
		<-ctx.Done()
		close(ended)
		return nil, ctx.Err()
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fd.Close() }()
	client, err := NewClient(fd, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = client.Resolve(context.Background(), pack(t, query(t, dns.TypeA))) }()
	<-started
	if _, err := client.Resolve(context.Background(), pack(t, query(t, dns.TypeMX))); err == nil {
		t.Fatal("compromised child exceeded parent bound")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("owner loss left DNS worker")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("owner loss left child request")
	}
}
