// Command bivouac manages ephemeral GitHub Actions runners in disposable
// guests. `biv` is the same binary under another name.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/engine"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/paths"
	"github.com/GomerPiles/bivouac/internal/provider/crosvm"
	"github.com/GomerPiles/bivouac/internal/provider/vz"
	"github.com/GomerPiles/bivouac/internal/vm"
	"github.com/GomerPiles/bivouac/internal/winrunner"
)

const usage = `usage: bivouac <command> [flags]

Control (durable; survive reboots):
  on        accept jobs
  drain     accept no new jobs, finish active jobs, dispose of guests, idle
  stop      cancel active jobs now, destroy guests, reclaim resources, idle
  off       drain, then the daemon exits and stays off
  status    mode, active guests, budgets, recent errors

Daemon:
  run       run the manager in the foreground
  install   opt in to starting the daemon at login (optional)
  uninstall remove the login item

Setup:
  doctor           check host, config, credentials, engines
  config validate  check the config file   (also: config example, config path)
  secret set       store a credential-store item from a file or stdin
  secret check     report whether an item exists   (also: secret delete)
  vz import        copy a Tart-format VM into the VM store as a baseline
  vz list          show guests bivouac owns and guests it does not
  vz cleanup       delete orphaned guests that carry bivouac's own metadata
  appsandbox inspect  read-only daemon/version/VM inventory (no startup)
  appsandbox broker   operator-started elevated lifecycle broker
  vmhost run          elevated foreground VM host (Windows HCS guests)
  vmhost install      register the optional VM host service (elevated; also: uninstall)
  vmhost start|stop   start or stop the installed service without elevation
  vmhost status       service state and VM host limits
  image build|inspect|cleanup prepare or inspect a direct HCS image (elevated)
  crosvm validate     credential-free Linux GPU/lifecycle/recovery test
  crosvm build-image  prepare and cleanly capture an independent Linux image
  crosvm cleanup      retry one exact recorded native validation instance
  version
`

type env struct {
	layout paths.Layout
	files  control.Files
}

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := dispatch(ctx, os.Args[1], os.Args[2:]); err != nil {
		if errors.Is(err, errUsage) {
			fmt.Fprint(os.Stderr, usage)
			return 2
		}
		fmt.Fprintln(os.Stderr, "bivouac:", err)
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		return 1
	}
	return 0
}

var errUsage = errors.New("usage")

func dispatch(ctx context.Context, cmd string, args []string) error {
	if cmd == "login-run" {
		return loginRun(ctx, args)
	}
	if cmd == "crosvm" {
		return crosvmCmd(ctx, args, os.Stdout)
	}
	if cmd == "guest" {
		if len(args) == 3 && args[0] == "macos" {
			return vz.RunGuest(ctx, args[1], args[2], os.Stdout)
		}
		if len(args) == 2 && args[0] == "linux" {
			return crosvm.RunLinuxGuest(ctx, args[1], os.Stdin, os.Stdout)
		}
		if len(args) == 2 && args[0] == "windows" {
			return winrunner.RunGuest(ctx, args[1], os.Stdout)
		}
		return errUsage
	}
	if cmd == "appsandbox" {
		return appsandboxCmd(ctx, args, os.Stdout)
	}
	if cmd == "vmhost" {
		return vmhostCmd(ctx, args, os.Stdout)
	}
	if cmd == "image" {
		return imageCmd(ctx, args, os.Stdout)
	}
	if cmd == "guest-agent" {
		if len(args) != 0 {
			return errUsage
		}
		return guestagent.RunAgent(ctx)
	}
	if cmd == "vm" {
		if len(args) == 0 || args[0] != "run" {
			return errUsage
		}
		opts, err := vm.ParseArgs(args[1:])
		if err != nil {
			return err
		}
		// The helper handles SIGTERM and SIGINT itself, logging the power-off
		// and waiting for the VM to stop before it releases the lock.
		return vm.RunHelper(context.WithoutCancel(ctx), opts, os.Stdout)
	}
	if cmd == "engine" {
		if len(args) == 1 {
			switch args[0] {
			case "check-isolation":
				_, err := vz.CheckIsolation(ctx)
				if err == nil {
					fmt.Println("isolation preflight available; no VM started")
				}
				return err
			case "relay":
				return vz.RunRelay(ctx, os.Stdin)
			case "listen":
				return engine.GuestListen(ctx)
			case "probe":
				return engine.Probe(ctx, engine.GuestSocket)
			case "dns":
				return engine.PublicDNS(ctx)
			}
		}
		if len(args) == 2 && args[0] == "dial" {
			return engine.GuestDial(ctx, args[1])
		}
		return errUsage
	}
	// The same native binary is copied into guests; this private adapter needs
	// neither host configuration nor the host's credential store.
	if cmd == "cache" && len(args) == 3 && args[0] == "proxy" {
		return cache.RunGuestProxy(ctx, args[1], args[2])
	}
	layout, err := paths.Resolve()
	if err != nil {
		return err
	}
	e := env{layout: layout, files: control.Files{Dir: layout.State}}
	switch cmd {
	case "on", "drain", "stop", "off":
		return e.setMode(ctx, control.Mode(cmd), args)
	case "status":
		return e.status(args)
	case "run":
		return e.run(ctx, args)
	case "install":
		return e.install(ctx)
	case "uninstall":
		return e.uninstall(ctx)
	case "doctor":
		return e.doctor(ctx, args)
	case "config":
		return e.configCmd(args)
	case "secret":
		return e.secretCmd(ctx, args)
	case "vz":
		return e.vzCmd(ctx, args)
	case "version":
		fmt.Println("bivouac", version())
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return errUsage
}

func version() string {
	v := "dev"
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 8 {
				v += "+" + s.Value[:8]
			}
		}
	}
	return v
}

func newID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func (e env) loadConfig(path string) (*config.Config, error) {
	if path == "" {
		path = e.layout.Config
	}
	c, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func parseFlags(name string, args []string, fn func(*flag.FlagSet)) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fn(fs)
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	return nil
}
