package winguest

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// scpSink is a one-file scp -t server, enough to check the client's framing.
func scpSink(t *testing.T, id *Identity, refuse bool) (*ssh.Client, chan []byte) {
	t.Helper()
	allow := id.Signer.PublicKey()
	host, guest := tcpPair(t)
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(key.Marshal(), allow.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("denied")
	}}
	config.AddHostKey(signer)
	received := make(chan []byte, 1)
	go func() {
		_, channels, requests, err := ssh.NewServerConn(guest, config)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(requests)
		for c := range channels {
			ch, reqs, err := c.Accept()
			if err != nil {
				return
			}
			go func() {
				for r := range reqs {
					if r.Type != "exec" {
						_ = r.Reply(false, nil)
						continue
					}
					_ = r.Reply(true, nil)
					in := bufio.NewReader(ch)
					if refuse {
						_, _ = ch.Write([]byte("\x02denied by guest\n"))
					} else {
						_, _ = ch.Write([]byte{0})
						header, _ := in.ReadString('\n')
						var mode string
						var size int64
						var name string
						_, _ = fmt.Sscanf(header, "%s %d %s", &mode, &size, &name)
						_, _ = ch.Write([]byte{0})
						body := make([]byte, size)
						_, _ = io.ReadFull(in, body)
						_, _ = in.ReadByte()
						_, _ = ch.Write([]byte{0})
						received <- append([]byte(name+":"), body...)
					}
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					_ = ch.Close()
				}
			}()
		}
	}()
	client, _, err := Connect(t.Context(), host, "ciuser", id, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, received
}

func newTestIdentity(t *testing.T) *Identity {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Clear)
	return id
}

func TestSendFramesOneFixedFile(t *testing.T) {
	id := newTestIdentity(t)
	client, received := scpSink(t, id, false)
	if err := Send(t.Context(), client, "bivouac-config.json", strings.NewReader(`{"ok":true}`), 11); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if string(got) != `bivouac-config.json:{"ok":true}` {
			t.Fatalf("guest received %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("transfer not received")
	}
}

func TestSendRefusesUnsafeNamesAndReportsGuestRefusal(t *testing.T) {
	id := newTestIdentity(t)
	client, _ := scpSink(t, id, true)
	for _, name := range []string{"", `..\x`, "a/b", "C:x", "two words", "x\n"} {
		if err := Send(t.Context(), client, name, strings.NewReader(""), 0); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	err := Send(t.Context(), client, "bivouac-helper.exe", strings.NewReader("x"), 1)
	if err == nil || strings.Contains(err.Error(), "denied by guest") {
		t.Fatal("guest refusal not reported safely", err)
	}
	if err := Send(t.Context(), client, "short.bin", strings.NewReader("x"), 5); err == nil {
		t.Fatal("short source accepted")
	}
}
