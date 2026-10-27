//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"

	"github.com/GomerPiles/bivouac/internal/guestagent"
)

// An in-memory private link separates agent/process compatibility from host
// networking. It uses the actual shared framing and Windows command jobs.
type pipeListener struct {
	ctx         context.Context
	cancel      context.CancelFunc
	connections chan net.Conn
}

func (l *pipeListener) Accept() (io.ReadWriteCloser, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.ctx.Done():
		return nil, l.ctx.Err()
	}
}
func (l *pipeListener) Close() error { l.cancel(); return nil }

type protocolFacts struct {
	Frames bool `json:"frames"`
	Input  bool `json:"input"`
	Exit   bool `json:"exit"`
}

func protocolSelftest(ctx context.Context) protocolFacts {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	listener := &pipeListener{ctx: ctx, cancel: cancel, connections: make(chan net.Conn)}
	done := make(chan struct{})
	go func() { defer close(done); _ = guestagent.Serve(ctx, listener) }()
	defer func() { cancel(); <-done }()
	dial := func(ctx context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		select {
		case listener.connections <- server:
			return client, nil
		case <-ctx.Done():
			_ = client.Close()
			_ = server.Close()
			return nil, ctx.Err()
		}
	}
	self, err := os.Executable()
	if err != nil {
		return protocolFacts{}
	}
	var facts protocolFacts
	var output boundedBuffer
	if guestagent.Run(ctx, dial, []string{self, "facts"}, nil, &output) == nil {
		var observed sessionFacts
		facts.Frames = decodeBounded(bytes.NewReader(output.data), &observed) == nil && observed.valid()
	}
	output = boundedBuffer{}
	if guestagent.Run(ctx, dial, []string{self, "echo"}, strings.NewReader("bivouac-sandbox-stdin-probe"), &output) == nil {
		var observed struct {
			Input bool `json:"input"`
		}
		facts.Input = json.Unmarshal(output.data, &observed) == nil && observed.Input
	}
	err = guestagent.Run(ctx, dial, []string{self, "expected-failure"}, nil, io.Discard)
	var exit *guestagent.ExitError
	facts.Exit = errors.As(err, &exit) && exit.Code == 1
	return facts
}
