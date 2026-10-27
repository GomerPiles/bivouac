//go:build windows

package winrunner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/engine"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"golang.org/x/sys/windows"
)

func TestGuestListenerRefusesExistingCancellation(t *testing.T) {
	root := guestTestRoot(t)
	if err := createRecord(root, "cancelled", false); err != nil {
		t.Fatal(err)
	}
	err := guestListener(t.Context(), Config{}, listenerOptions{base: root.Name(), desktop: func() error { t.Fatal("cancelled listener reached desktop/input/process setup"); return nil }, cancel: func() error { t.Fatal("absent listener signalled"); return nil }})
	if err == nil || err.Error() != "listener launch cancelled" {
		t.Fatal("guestListener ignored cancellation", err)
	}
	if raw, e := root.ReadFile("runner.exit"); e != nil || string(raw) != `{"code":1}` {
		t.Fatal("missing cancellation exit record", e)
	}
	for _, name := range []string{"launch-once", "listener.json", "runner.log"} {
		if _, e := root.Lstat(name); !os.IsNotExist(e) {
			t.Fatal("cancelled listener consumed setup state")
		}
	}
}

func TestStopRecordsCancellationWhileReceiveLockHeld(t *testing.T) {
	root := guestTestRoot(t)
	path, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), ".receive.lock"))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(lock) }()
	if err := stopGuest(root, func() error { t.Fatal("listener does not exist"); return nil }); err != nil {
		t.Fatal(err)
	}
	if exists, err := guestFileExists(root, "cancelled"); err != nil || !exists {
		t.Fatal("stop failed during start's receive lock")
	}
}

func TestTrampolineInjectedContextRefusals(t *testing.T) {
	good := detachedContext{Session: guestagent.RunnerContext{UserSID: "S-1-5-21-1-2-3-1001", ExpectedSID: "S-1-5-21-1-2-3-1001", ProcessSession: 2, ConsoleSession: 2, Elevated: true, Elevation: 2}, Desktop: true}
	for _, mode := range []string{"valid", "wrong SID", "unelevated", "wrong session", "wrong desktop", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			facts := good
			switch mode {
			case "wrong SID":
				facts.Session.UserSID = "S-1-5-21-1-2-3-1002"
			case "unelevated":
				facts.Session.Elevated = false
			case "wrong session":
				facts.Session.ProcessSession = 3
			case "wrong desktop":
				facts.Desktop = false
			}
			reached := false
			err := detachedInContext(guestagent.WindowsPath, func() (detachedContext, error) {
				if mode == "unavailable" {
					return facts, errors.New("native details")
				}
				return facts, nil
			}, func() error { reached = true; return nil })
			if reached != (mode == "valid") || (err == nil) != (mode == "valid") {
				t.Fatal("trampoline context decision differs")
			}
		})
	}
}

func TestDetachedListenerLaunchContract(t *testing.T) {
	cmd := runnerChildCommand(filepath.Join(guestBase, "bivouac.exe"), "listener")
	want := []string{filepath.Join(guestBase, "bivouac.exe"), "guest", "windows", "listener"}
	if !reflect.DeepEqual(cmd.Args, want) || cmd.Dir != guestBase || cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatal("detached listener inherited request streams or changed argv")
	}
	flags := cmd.SysProcAttr.CreationFlags
	if flags&windows.CREATE_BREAKAWAY_FROM_JOB != 0 || flags&windows.DETACHED_PROCESS == 0 || flags&windows.CREATE_NEW_CONSOLE != 0 {
		t.Fatal("listener supervisor has unexpected process flags")
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
		case <-finished: //nolint:errcheck // Only shutdown matters, not its result.
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

func TestTrampolineRefusesHostExecution(t *testing.T) {
	if err := RunGuest(t.Context(), "detached", io.Discard); err == nil {
		t.Fatal("trampoline ran from an uninstalled executable")
	}
	cmd, err := runnerTaskCommand(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Args) != 4 || cmd.Args[1] != "/Run" || cmd.Args[2] != "/TN" || cmd.Args[3] != "bivouac-guest-runner" || cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatal("dispatch argv or streams changed")
	}
}
