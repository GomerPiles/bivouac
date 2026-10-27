//go:build windows

package winrunner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/engine"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type listenerIdentity struct {
	PID      uint32 `json:"pid"`
	Creation uint64 `json:"creation"`
	Image    string `json:"image"`
}

func currentPreflightFacts() (preflightFacts, error) {
	var f preflightFacts
	var err error
	f.computer, err = os.Hostname()
	if err != nil {
		return f, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return f, err
	}
	f.user, _, _, err = user.User.Sid.LookupAccount("")
	if err != nil {
		return f, err
	}
	f.console = windows.WTSGetActiveConsoleSessionId()
	if f.console == 0 || f.console == ^uint32(0) {
		return f, nil
	}
	var buffer *uint16
	var size uint32
	dll := windows.NewLazySystemDLL("wtsapi32.dll")
	// #nosec G103 -- WTS allocates the bounded UTF-16 result, freed below.
	ok, _, _ := dll.NewProc("WTSQuerySessionInformationW").Call(0, uintptr(f.console), 5, uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&size)))
	if buffer != nil {
		defer func() {
			// #nosec G103 -- Release the buffer allocated by WTSQuerySessionInformationW.
			_, _, _ = dll.NewProc("WTSFreeMemory").Call(uintptr(unsafe.Pointer(buffer)))
		}()
	}
	if ok == 0 || buffer == nil || size < 2 || size > 512 || size%2 != 0 {
		return f, errors.New("console account unavailable")
	}
	// #nosec G103 -- WTS returned size bytes; enforce a small even bound above.
	f.consoleUser = windows.UTF16ToString(unsafe.Slice(buffer, int(size/2)))
	f.process, f.desktop, err = interactiveDesktop()
	if err != nil {
		return f, err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\Setup`, registry.QUERY_VALUE)
	if err != nil {
		return f, err
	}
	defer func() { _ = key.Close() }()
	f.setup, _, err = key.GetIntegerValue("SystemSetupInProgress")
	if err != nil {
		return f, err
	}
	f.oobe, _, err = key.GetIntegerValue("OOBEInProgress")
	if err != nil {
		return f, err
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return f, err
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), "explorer.exe") {
			var session uint32
			if windows.ProcessIdToSessionId(entry.ProcessID, &session) == nil && session == f.console {
				f.explorer = true
				return f, nil
			}
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return f, err
	}
	return f, nil
}

func guestPreflight(ctx context.Context, cfg Config, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	proof, err := waitPreflight(ctx, cfg, currentPreflightFacts, func(ctx context.Context) error { return pauseGuest(ctx, 500*time.Millisecond) })
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(proof)
}

func installGuestFile(root *os.Root, source, target string, limit int64) error {
	in, err := root.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > limit {
		return errors.New("invalid bounded delivered guest file")
	}
	// Fixed private staging names fail closed after interruption; no replay.
	temporary := target + ".install"
	out, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(temporary) }()
	n, copyErr := io.Copy(out, io.LimitReader(in, limit+1))
	syncErr := out.Sync()
	if err := errors.Join(copyErr, syncErr, out.Close()); err != nil {
		return err
	}
	if n != info.Size() || n > limit {
		return errors.New("delivered guest file size differs")
	}
	return root.Rename(temporary, target)
}

func guestPrepare(ctx context.Context, out io.Writer) error {
	if err := checkGuestExecutable(); err != nil {
		return err
	}
	guard, err := guestagent.LockGuestDirectory()
	if err != nil {
		return errors.New("guest preparation storage unavailable or busy")
	}
	defer func() { _ = guard.Close() }()
	root, err := os.OpenRoot(guestBase)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if exists, err := guestFileExists(root, "launched"); err != nil || exists {
		return errors.New("guest already launched")
	}
	cfg, err := loadGuestConfigFile("bivouac-config.json")
	if err != nil {
		return err
	}
	previous, err := readGuestFile(filepath.Join(guestBase, "config.json"), 65536)
	if err == nil {
		if err := checkPrepareInstance(previous, cfg); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, pair := range [][2]string{{"bivouac-helper.exe", "bivouac.exe"}, {"bivouac-config.json", "config.json"}} {
		if err := installGuestFile(root, pair[0], pair[1], 1<<30); err != nil {
			return err
		}
	}
	adapters, err := net.Interfaces()
	if err != nil {
		return errors.New("enumerate guest adapters")
	}
	plan, err := networkPlan(cfg, adapters)
	if err != nil {
		return err
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	for _, args := range plan {
		step, cancel := context.WithTimeout(ctx, 30*time.Second)
		cmd := exec.CommandContext(step, filepath.Join(system, "netsh.exe"), args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		err = cmd.Run() // Tool output is discarded, including failures.
		cancel()
		if err != nil {
			return errors.New("configure static guest IPv4 network")
		}
	}
	if cfg.Archive {
		archive := filepath.Join(guestBase, "bivouac-runner.zip")
		if err := VerifyArchive(archive, cfg.ArchiveSHA256); err != nil {
			return err
		}
		if err := extractRunner(ctx, archive, cfg.RunnerDir); err != nil {
			return err
		}
		if err := root.Remove("bivouac-runner.zip"); err != nil {
			return err
		}
	}
	listener, err := os.Lstat(filepath.Join(cfg.RunnerDir, "bin", "Runner.Listener.exe"))
	if err != nil || !listener.Mode().IsRegular() {
		return errors.New("generic official runner is not installed")
	}
	for _, name := range []string{".runner", ".credentials"} {
		if _, err := os.Lstat(filepath.Join(cfg.RunnerDir, name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("baseline contains a configured runner")
		}
	}
	// This command already runs in the agent's console session; no probe task.
	facts, err := currentPreflightFacts()
	if err != nil || !preflightReady(cfg, facts) {
		return errors.New("guest console desktop proof unavailable")
	}
	proof := desktopProof{true, facts.console, facts.desktop}
	if err := writeGuestJSON("desktop.json", proof); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(proof)
}

func guestStart(ctx context.Context, cfg Config) error {
	guard, err := guestagent.LockGuestDirectory()
	if err != nil {
		return errors.New("guest launch storage unavailable or busy")
	}
	defer func() { _ = guard.Close() }()
	root, err := os.OpenRoot(guestBase)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := dispatchRunner(ctx, root, "listener"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		_, live, err := recordedListener(cfg)
		if err != nil {
			return err
		}
		if live {
			return nil
		}
		if exited, err := guestFileExists(root, "runner.exit"); err != nil || exited {
			return errors.New("listener exited before startup proof")
		}
		if pauseGuest(ctx, 200*time.Millisecond) != nil {
			return errors.New("interactive guest operation timed out")
		}
	}
}

func guestClock(input io.Reader, out io.Writer) error {
	value, err := parseClock(input)
	if err != nil {
		return err
	}
	// #nosec G115 -- parseClock bounds the year; all other calendar fields fit WORD.
	system := windows.Systemtime{Year: uint16(value.Year()), Month: uint16(value.Month()), Day: uint16(value.Day()), Hour: uint16(value.Hour()), Minute: uint16(value.Minute()), Second: uint16(value.Second()), Milliseconds: uint16(value.Nanosecond() / 1e6)}
	// #nosec G103 -- SetSystemTime reads one documented SYSTEMTIME structure.
	ok, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetSystemTime").Call(uintptr(unsafe.Pointer(&system)))
	if ok == 0 {
		return errors.New("set guest UTC clock failed")
	}
	_, err = fmt.Fprintln(out, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

type guestStdio struct {
	io.Reader
	io.Writer
}

func (guestStdio) Close() error { return errors.Join(os.Stdin.Close(), os.Stdout.Close()) }

const cacheConnections = 64

type cachePort struct {
	Port int `json:"port"`
}

// First publish a small JSON line, then start the opaque engine framing. The
// host consumes that line before Relay and uses the port in the existing cache
// bootstrap URL. No capability or HTTP data is written outside the stream.
func cacheListen(ctx context.Context, stream io.ReadWriteCloser, publish func(cachePort) error) error {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("guest cache loopback listener unavailable")
	}
	defer func() { _ = l.Close() }()
	port := cachePort{l.Addr().(*net.TCPAddr).Port}
	if err := publish(port); err != nil {
		return err
	}
	if err := json.NewEncoder(stream).Encode(port); err != nil {
		return err
	}
	return engine.Listen(ctx, stream, l, cacheConnections)
}
