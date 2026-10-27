//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestBrokerOnlyQueriesForAuthorizedFixedRequest(t *testing.T) {
	const account = "S-1-5-21-1-2-3-1001"
	for _, test := range []struct {
		name, caller, op string
		protocol         int
		want             bool
	}{
		{"authorized", account, "candidates", 1, true},
		{"foreign", "S-1-5-21-1-2-3-1002", "candidates", 1, false},
		{"anonymous", "S-1-5-7", "candidates", 1, false},
		{"wrong protocol", account, "candidates", 2, false},
		{"destroy", account, "destroy", 1, false},
		{"arbitrary command", account, "exec", 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			queries := 0
			broker := metadataBroker{account: account, identify: func(net.Conn) (string, error) { return test.caller, nil }, query: func(context.Context, io.Writer) error { queries++; return nil }, seen: map[string]bool{}}
			// A valid query produces an empty, bounded inventory without HCS.
			broker.query = func(_ context.Context, out io.Writer) error {
				queries++
				_, err := io.WriteString(out, "[]")
				return err
			}
			request := brokerRequest{Protocol: test.protocol, Op: test.op, Nonce: "11111111-2222-4333-8444-555555555555"}
			response, accepted := exchangeBroker(t, &broker, request)
			if accepted != test.want || (response.Code == "ok") != test.want || (queries == 1) != test.want {
				t.Fatal("broker authorization or dispatch differs")
			}
			if response.Nonce != request.Nonce {
				t.Fatal("response nonce differs")
			}
			if test.want {
				response, accepted = exchangeBroker(t, &broker, request)
				if accepted || response.Code != "refused" || queries != 1 {
					t.Fatal("replayed request queried HCS")
				}
			}
		})
	}
}

func exchangeBroker(t *testing.T, broker *metadataBroker, request brokerRequest) (brokerResponse, bool) {
	t.Helper()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan bool, 1)
	go func() { done <- broker.handle(context.Background(), server) }()
	if writeBrokerFrame(client, request) != nil {
		t.Fatal("request write failed")
	}
	var response brokerResponse
	if readBrokerFrame(client, 65536, &response) != nil {
		t.Fatal("response read failed")
	}
	return response, <-done
}

func TestBrokerRejectsOversizedAndUnknownFields(t *testing.T) {
	var header bytes.Buffer
	_ = binary.Write(&header, binary.BigEndian, uint32(1025))
	var request brokerRequest
	if readBrokerFrame(&header, 1024, &request) == nil {
		t.Fatal("oversized request accepted")
	}
	data := []byte(`{"protocol":1,"op":"candidates","nonce":"11111111-2222-4333-8444-555555555555","path":"untrusted"}`)
	var frame bytes.Buffer
	_ = binary.Write(&frame, binary.BigEndian, uint32(len(data))) // #nosec G115 -- Fixed small test input.
	_, _ = frame.Write(data)
	if readBrokerFrame(&frame, 1024, &request) == nil {
		t.Fatal("untrusted path field accepted")
	}
	if _, err := brokerPipe(`..\foreign`); err == nil {
		t.Fatal("arbitrary endpoint name accepted")
	}
	descriptor, err := brokerDescriptor("S-1-5-21-1-2-3-1001")
	if err != nil || !strings.HasPrefix(descriptor, "O:BAD:P") || brokerClientAccess&windows.FILE_APPEND_DATA != 0 {
		t.Fatal("pipe ownership or client mask differs")
	}
	if _, err := brokerDescriptor("S-1-5-21-1-2-3-1001)(A;;GA;;;WD)"); err == nil {
		t.Fatal("SID injection accepted")
	}
}

func TestBrokerClientRejectsUserOwnedSquatter(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires an ordinary-user pipe creator")
	}
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	name, err := brokerPipe(id)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := winio.ListenPipe(name, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if duplicate, err := winio.ListenPipe(name, nil); err == nil {
		_ = duplicate.Close()
		t.Fatal("preexisting endpoint was adopted")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := dialBroker(ctx, id); err == nil {
		_ = conn.Close()
		t.Fatal("user-owned fake broker trusted")
	}
	<-done
}

func TestBrokerResponseContainsNoOpaqueNativeOutput(t *testing.T) {
	broker := metadataBroker{account: "S-1-5-21-1-2-3-1001", identify: func(net.Conn) (string, error) { return "S-1-5-21-1-2-3-1001", nil }, query: func(_ context.Context, out io.Writer) error {
		return json.NewEncoder(out).Encode(map[string]string{"opaque": "must not cross broker"})
	}, seen: map[string]bool{}}
	response, accepted := exchangeBroker(t, &broker, brokerRequest{Protocol: 1, Op: "candidates", Nonce: "11111111-2222-4333-8444-555555555555"})
	if accepted || response.Code != "unavailable" || len(response.Candidates) != 0 {
		t.Fatal("opaque native response escaped")
	}
}

func TestBrokerPipeChecksRealCallerAndDeniesAnonymous(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	account := user.User.Sid.String()
	descriptor, err := brokerDescriptor(account)
	if err != nil {
		t.Fatal(err)
	}
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	name, err := brokerPipe(id)
	if err != nil {
		t.Fatal(err)
	}
	// The unelevated fixture needs an extra server-access ACE to serve;
	// the real broker gets this through its enabled Administrators SID.
	// Keep the same anonymous exclusion and identification-only client path.
	fixtureDescriptor := strings.TrimPrefix(descriptor, "O:BA") + "(A;;GA;;;" + account + ")"
	listener, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: fixtureDescriptor})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	broker := metadataBroker{account: account, identify: brokerCaller, query: func(_ context.Context, out io.Writer) error { _, err := io.WriteString(out, "[]"); return err }, seen: map[string]bool{}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	done := make(chan bool, 1)
	go func() {
		for range 2 {
			conn, err := listener.Accept()
			if err != nil || !broker.handle(ctx, conn) {
				done <- false
				return
			}
		}
		done <- true
	}()
	for index := range 2 {
		conn, err := winio.DialPipeAccessImpLevel(ctx, name, brokerClientAccess, winio.PipeImpLevelIdentification)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		if writeBrokerFrame(conn, brokerRequest{Protocol: 1, Op: "candidates", Nonce: nonce}) != nil {
			t.Fatal("ordinary query write failed")
		}
		var response brokerResponse
		err = readBrokerFrame(conn, 65536, &response)
		_ = conn.Close()
		if err != nil || response.Code != "ok" || response.Nonce != nonce {
			t.Fatal("real caller was not identified")
		}
		if index == 0 {
			if denied, err := anonymousBrokerDial(ctx, name); err != nil || !denied {
				t.Fatal("anonymous fixture access was not denied")
			}
		}
	}
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("real pipe dispatch failed")
		}
	case <-ctx.Done():
		t.Fatal("real pipe dispatch timed out")
	}
}
