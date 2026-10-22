//go:build windows

package winrunner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/engine"
	"golang.org/x/sys/windows"
)

func TestDetachedListenerLaunchContract(t *testing.T) {
	cmd := detachedListenerCommand()
	want := []string{filepath.Join(guestBase, "bivouac.exe"), "guest", "windows", "listener"}
	if !reflect.DeepEqual(cmd.Args, want) || cmd.Dir != guestBase || cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatal("detached listener inherited request streams or changed argv")
	}
	flags := cmd.SysProcAttr.CreationFlags
	if flags&windows.CREATE_BREAKAWAY_FROM_JOB == 0 || flags&windows.DETACHED_PROCESS == 0 || flags&windows.CREATE_NEW_CONSOLE != 0 {
		t.Fatal("listener supervisor is not detached from the command job")
	}
}

func TestListenerIdentityRefusals(t *testing.T) {
	cfg := Config{RunnerDir: `C:\actions-runner`}
	owned := listenerIdentity{PID: 123, Creation: 456, Image: filepath.Join(cfg.RunnerDir, "bin", "Runner.Listener.exe")}
	data, err := json.Marshal(owned)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		current listenerIdentity
		live    bool
		err     error
		wantErr bool
	}{
		{"match", owned, true, nil, false},
		{"exited", listenerIdentity{}, false, nil, false},
		{"reused", listenerIdentity{owned.PID, 999, owned.Image}, true, nil, true},
		{"different path", listenerIdentity{owned.PID, owned.Creation, `C:\other.exe`}, true, nil, true},
		{"unverifiable", listenerIdentity{}, false, errors.New("access denied"), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, live, err := checkListenerIdentity(cfg, data, func(pid uint32) (listenerIdentity, bool, error) {
				if pid != owned.PID {
					t.Fatal("queried another process")
				}
				return test.current, test.live, test.err
			})
			if (err != nil) != test.wantErr || live != (test.live && !test.wantErr) {
				t.Fatal(live, err)
			}
		})
	}
	for _, invalid := range []string{`{}`, `{"pid":123,"creation":456,"image":"C:\\other.exe"}`, `{"pid":0}`, "invalid"} {
		called := false
		if _, _, err := checkListenerIdentity(cfg, []byte(invalid), func(uint32) (listenerIdentity, bool, error) { called = true; return owned, true, nil }); err == nil || called {
			t.Fatal("invalid record reached native identity lookup")
		}
	}
	actual, live, err := processIdentity(windows.GetCurrentProcessId())
	if err != nil || !live || actual.Creation == 0 || actual.Image == "" {
		t.Fatal("read-only native process identity failed", err)
	}
}

func TestInstallDeliveredGuestFiles(t *testing.T) {
	root := guestTestRoot(t)
	if err := root.WriteFile("bivouac-config.json", []byte("delivered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installGuestFile(root, "bivouac-config.json", "config.json", 8); err == nil {
		t.Fatal("accepted oversize delivery")
	}
	if err := installGuestFile(root, "bivouac-config.json", "config.json", 64); err != nil {
		t.Fatal(err)
	}
	if data, err := root.ReadFile("config.json"); err != nil || string(data) != "delivered" {
		t.Fatal("installed content differs", err)
	}
	if err := root.WriteFile("bivouac-config.json", []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installGuestFile(root, "bivouac-config.json", "config.json", 64); err != nil {
		t.Fatal("atomic replacement failed", err)
	}
}

func TestCacheListenPortPublicationAndOpaqueRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	guest, host := net.Pipe()
	defer func() { _ = host.Close() }()
	published := make(chan cachePort, 1)
	done := make(chan error, 1)
	go func() { done <- cacheListen(ctx, guest, func(port cachePort) error { published <- port; return nil }) }()
	reader := bufio.NewReader(host)
	line, err := reader.ReadString('\n')
	if err != nil || len(line) > 64 {
		t.Fatal("missing bounded port prelude", err)
	}
	var advertised cachePort
	if err := json.Unmarshal([]byte(line), &advertised); err != nil || advertised.Port < 1 || advertised.Port > 65535 {
		t.Fatal("invalid published cache port", err)
	}
	if advertised != <-published {
		t.Fatal("port prelude and published file differ")
	}
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- engine.Relay(ctx, host, func(context.Context) (net.Conn, error) {
			left, right := net.Pipe()
			go func() { defer func() { _ = right.Close() }(); _, _ = io.Copy(right, right) }()
			return left, nil
		}, cacheConnections)
	}()
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(advertised.Port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte{0, 255, 13, 10, 'o', 'k'}
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil || !reflect.DeepEqual(got, payload) {
		t.Fatal("cache relay changed opaque bytes", err)
	}
	_ = host.Close()
	for _, finished := range []chan error{done, relayDone} {
		select {
		case <-finished:
		case <-ctx.Done():
			t.Fatal("cache stream shutdown did not finish")
		}
	}
	if c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(advertised.Port)), time.Second); err == nil {
		_ = c.Close()
		t.Fatal("cache listener survived stream closure")
	}
}

func TestCacheListenPublicationFailureClosesListener(t *testing.T) {
	guest, host := net.Pipe()
	defer func() { _ = guest.Close(); _ = host.Close() }()
	failure := errors.New("publication refused")
	var port cachePort
	err := cacheListen(t.Context(), guest, func(p cachePort) error { port = p; return failure })
	if !errors.Is(err, failure) {
		t.Fatal("publication failure ignored", err)
	}
	if c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port.Port)), time.Second); err == nil {
		_ = c.Close()
		t.Fatal("listener leaked after publication failure")
	}
}

func TestPrepareRefusesHostExecution(t *testing.T) {
	// Preparing on the host must refuse before touching the guest directory.
	if err := RunGuest(t.Context(), "prepare", io.Discard); err == nil {
		t.Fatal("prepare ran on the host")
	}
}
