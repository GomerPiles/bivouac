//go:build windows

package guestagent

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"unsafe"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

type sessionFacts struct {
	process, console, elevation uint32
	elevated                    bool
	user                        string // SID only, never logged.
}

const (
	elevationDefault = 1 // TOKEN_ELEVATION_TYPE: no split token.
	elevationFull    = 2
)

func sessionAllowed(f sessionFacts, expected string) bool {
	return f.console != ^uint32(0) && f.process != 0 && f.process == f.console &&
		f.elevated && (f.elevation == elevationFull || f.elevation == elevationDefault) &&
		expected != "" && f.user == expected
}

func currentSession() (sessionFacts, error) {
	var f sessionFacts
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &f.process); err != nil {
		return f, err
	}
	f.console = windows.WTSGetActiveConsoleSessionId()
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return f, err
	}
	f.user = user.User.Sid.String()
	var elevated, returned uint32
	// #nosec G103 -- Fixed DWORD token-information outputs.
	if err := windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevated)), 4, &returned); err != nil {
		return f, err
	}
	if returned != 4 {
		return f, errors.New("invalid token elevation")
	}
	f.elevated = elevated != 0
	// #nosec G103 -- Fixed DWORD token-information output.
	if err := windows.GetTokenInformation(token, windows.TokenElevationType, (*byte)(unsafe.Pointer(&f.elevation)), 4, &returned); err != nil {
		return f, err
	}
	if returned != 4 {
		return f, errors.New("invalid token type")
	}
	return f, nil
}

// RunAgent requires an explicit fixed account configuration on Windows.
func RunAgent(context.Context) error { return errors.New("windows guest agent requires --user") }

// RunCLI serves as `guest-agent --user <account>` or receives one fixed asset.
// The image's protected scheduled-task action pins --user; the account is
// resolved once to a SID, then checked against fresh process facts at startup
// and on every accepted connection. Receiver children inherit that identity.
func RunCLI(ctx context.Context, args []string, stdin io.Reader) error {
	if len(args) > 0 && args[0] == "selftest" {
		return selftest(ctx, args[1:], os.Stdout)
	}
	if len(args) > 0 && args[0] == "receive" {
		if len(args) != 4 {
			return errors.New("invalid receiver arguments")
		}
		size, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			return errors.New("invalid receiver size")
		}
		return receiveGuest(ctx, args[1], size, args[3], stdin)
	}
	flags := flag.NewFlagSet("guest-agent", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	user := flags.String("user", "", "fixed console account")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *user == "" {
		return errors.New("windows guest agent requires --user")
	}
	sid, _, kind, err := windows.LookupSID("", *user)
	if err != nil || kind != windows.SidTypeUser {
		return errors.New("agent account unavailable")
	}
	expected := sid.String()
	check := func() bool { f, err := currentSession(); return err == nil && sessionAllowed(f, expected) }
	if !check() {
		return errors.New("agent session refused")
	}
	dir, err := openGuestDirectory(agentLogDirectory)
	if err != nil {
		return errors.New("agent storage unavailable")
	}
	defer dir.Close()
	log, err := newAgentLog(dir)
	if err != nil {
		return errors.New("agent log unavailable")
	}
	defer func() { _ = log.Close() }()
	logger := slog.New(slog.NewJSONHandler(log, nil))
	logger.Info("agent_start", "protocol", Version)
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	guarded := newSessionListener(serveCtx, check, logger, func() (Listener, error) {
		return listenWindows(func(a *winio.HvsockAddr) (net.Listener, error) { return winio.ListenHvsock(a) })
	})
	guarded.cancel = cancel
	defer func() { _ = guarded.Close() }()
	err = Serve(serveCtx, guarded)
	logger.Info("agent_stop")
	if guarded.refused {
		return errors.New("agent session refused")
	}
	if err != nil || ctx.Err() == nil {
		return errors.New("agent listener ended")
	}
	return nil
}
