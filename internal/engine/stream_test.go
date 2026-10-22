package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Preserve Unix-socket coverage on guest platforms; Windows exercises the
// same stream protocol through a test-only loopback listener.
func streamListener(t *testing.T) net.Listener {
	t.Helper()
	network, address := "tcp4", "127.0.0.1:0"
	if runtime.GOOS != "windows" {
		dir, err := os.MkdirTemp("/tmp", "biv-engine-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		network, address = "unix", filepath.Join(dir, "api.sock")
	}
	l, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestRejectMalformedFrames(t *testing.T) {
	for _, f := range []frame{{kind: 0, id: 1}, {kind: openFrame, id: 0}, {kind: openFrame, id: 1, data: []byte("target")}, {kind: dataFrame, id: 1}, {kind: 6, id: 1}} {
		var b bytes.Buffer
		_ = (&writer{out: &b}).send(f)
		if _, err := readFrame(&b); err == nil {
			t.Fatalf("accepted %+v", f)
		}
	}
	var h [9]byte
	h[0] = dataFrame
	binary.BigEndian.PutUint32(h[1:5], 1)
	binary.BigEndian.PutUint32(h[5:], maxFrame+1)
	if _, err := readFrame(bytes.NewReader(h[:])); err == nil {
		t.Fatal("accepted oversized frame")
	}
}

func TestConcurrentStreamsBackpressureAndTransportLoss(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	left, right := net.Pipe()
	l := streamListener(t)
	server := streamListener(t)
	defer func() { _ = server.Close() }()
	go func() {
		for {
			c, err := server.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	relayDone, guestDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(relayDone)
		_ = Relay(ctx, left, func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, server.Addr().Network(), server.Addr().String())
		}, ContainerConnections)
	}()
	go func() { defer close(guestDone); _ = Listen(ctx, right, l, ContainerConnections) }()
	var wg sync.WaitGroup
	for _, i := range []byte{0, 1, 2, 3} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial(l.Addr().Network(), l.Addr().String())
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(8 * time.Second))
			payload := bytes.Repeat([]byte{i, 0, 255, 13, 10}, 500000)
			writeDone := make(chan error, 1)
			go func() { _, err := c.Write(payload); writeDone <- err }()
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(c, got); err != nil {
				t.Error(err)
				return
			}
			if err = <-writeDone; err != nil {
				t.Error(err)
			}
			if !bytes.Equal(payload, got) {
				t.Error("opaque payload changed")
			}
		}()
	}
	wg.Wait()
	_ = left.Close()
	for _, done := range []chan struct{}{relayDone, guestDone} {
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal("transport loss did not close all sessions")
		}
	}
	if c, err := net.Dial(l.Addr().Network(), l.Addr().String()); err == nil {
		_ = c.Close()
		t.Fatal("listener survived transport loss")
	}
}

func TestConnectionLimitAndReusedID(t *testing.T) {
	for _, limit := range []int{ContainerConnections, 64} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) { testConnectionLimitAndReusedID(t, limit) })
	}
}

func testConnectionLimitAndReusedID(t *testing.T, limit int) {
	t.Helper()
	if limit < 1 || limit > 64 {
		t.Fatal("test limit outside supported bounds")
	}
	nativeLimit := uint32(limit) // #nosec G115 -- The helper accepts only 1..64 above.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	dials := make(chan struct{}, limit+1)
	done := make(chan error, 1)
	go func() {
		done <- Relay(ctx, a, func(ctx context.Context) (net.Conn, error) { dials <- struct{}{}; <-ctx.Done(); return nil, ctx.Err() }, limit)
	}()
	w := writer{out: b}
	for i := uint32(1); i <= nativeLimit; i++ {
		if err := w.send(frame{kind: openFrame, id: i}); err != nil {
			t.Fatal(err)
		}
	}
	for range limit {
		select {
		case <-dials:
		case <-time.After(time.Second):
			t.Fatal("dial missing")
		}
	}
	reject := make(chan frame, 1)
	go func() { f, _ := readFrame(b); reject <- f }()
	if err := w.send(frame{kind: openFrame, id: nativeLimit + 1}); err != nil {
		t.Fatal(err)
	}
	if f := <-reject; f.kind != closeFrame || f.id != nativeLimit+1 {
		t.Fatalf("limit response: %+v", f)
	}
	select {
	case <-dials:
		t.Fatal("dial exceeded limit")
	default:
	}
	if err := w.send(frame{kind: openFrame, id: 1}); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reused ID accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("reused ID did not stop relay")
	}
}

func TestListenConnectionLimits(t *testing.T) {
	for _, limit := range []int{ContainerConnections, 64} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			a, b := net.Pipe()
			defer func() { _ = b.Close() }()
			l := streamListener(t)
			done := make(chan error, 1)
			go func() { done <- Listen(ctx, a, l, limit) }()
			_ = b.SetDeadline(time.Now().Add(5 * time.Second))
			for i := range limit {
				c, err := net.Dial(l.Addr().Network(), l.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = c.Close() })
				f, err := readFrame(b)
				if err != nil || f.kind != openFrame || f.id != uint32(i+1) {
					t.Fatal("missing accepted connection", f, err)
				}
			}
			c, err := net.Dial(l.Addr().Network(), l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			var one [1]byte
			if n, err := c.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatal("over-limit guest connection was not closed", n, err)
			}
			_ = b.Close()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("limit test did not shut down")
			}
		})
	}
}

func TestInvalidConnectionLimits(t *testing.T) {
	for _, limit := range []int{-1, 0, 65} {
		a, b := net.Pipe()
		l := streamListener(t)
		if err := Listen(t.Context(), a, l, limit); err == nil {
			t.Fatal("invalid listener limit accepted")
		}
		if err := Relay(t.Context(), a, nil, limit); err == nil {
			t.Fatal("invalid relay limit accepted")
		}
		_ = a.Close()
		_ = b.Close()
	}
}

func TestFixedEngineSockets(t *testing.T) {
	for _, v := range []string{"unix:///personal.sock", "tcp://localhost:2375", "", "Docker"} {
		if _, err := Socket(v); err == nil {
			t.Fatalf("accepted %q", v)
		}
	}
	for _, v := range []string{"docker", "podman"} {
		if _, err := Socket(v); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHalfClosedUpload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	api := streamListener(t)
	backend := streamListener(t)
	defer func() { _ = backend.Close() }()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		body, err := io.ReadAll(c)
		if err == nil {
			_, _ = c.Write(append([]byte("reply:"), body...))
		}
	}()
	a, b := net.Pipe()
	done := make(chan struct{}, 2)
	go func() {
		_ = Relay(ctx, a, func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, backend.Addr().Network(), backend.Addr().String())
		}, ContainerConnections)
		done <- struct{}{}
	}()
	go func() { _ = Listen(ctx, b, api, ContainerConnections); done <- struct{}{} }()
	c, err := net.Dial(api.Addr().Network(), api.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte("binary-upload")); err != nil {
		t.Fatal(err)
	}
	if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	_ = c.Close()
	if err != nil || string(got) != "reply:binary-upload" {
		t.Fatalf("half-close reply: %q %v", got, err)
	}
	cancel()
	for range 2 {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("half-close transport did not stop")
		}
	}
}
