package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/install"
	"github.com/GomerPiles/bivouac/internal/manager"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/vz"
	"github.com/GomerPiles/bivouac/internal/secret"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/vm"
)

type flagSet = flag.FlagSet

// setMode records the operator's intent and nudges the daemon.
func (e env) setMode(ctx context.Context, mode control.Mode, args []string) error {
	var wait bool
	if err := parseFlags(string(mode), args, func(fs *flag.FlagSet) {
		fs.BoolVar(&wait, "wait", false, "wait until the daemon reaches the resulting state")
	}); err != nil {
		return err
	}
	if err := e.layout.Ensure(); err != nil {
		return err
	}
	if err := e.files.WriteMode(mode); err != nil {
		return err
	}
	woke, err := e.files.Wake()
	if err != nil {
		return err
	}
	active, pending := 0, 0
	if s, _ := e.files.ReadStatus(); s != nil && e.files.Alive() {
		active = s.Budgets.Active
		pending = len(s.PendingCleanup)
	}
	switch mode {
	case control.ModeOn:
		fmt.Println("bivouac: ON  - accepting jobs")
	case control.ModeDrain:
		fmt.Printf("bivouac: DRAIN - no new jobs; %d active guest(s) finish, then idle (daemon stays)\n", active)
	case control.ModeStop:
		fmt.Printf("bivouac: STOP - cancelling %d active guest(s) and reclaiming resources now; then idle (daemon stays)\n", active)
	case control.ModeOff:
		fmt.Printf("bivouac: OFF - %d active guest(s) finish, then the daemon exits and stays off across reboots\n", active)
	}
	if pending > 0 {
		fmt.Printf("%d runner registration(s) await cleanup; drain/off wait for these too\n", pending)
	}
	if !woke {
		if mode == control.ModeOn {
			if _, loaded, _ := install.Installed(ctx); loaded {
				if err := install.Kickstart(ctx); err != nil {
					return err
				}
				fmt.Println("daemon started through the login item")
			} else {
				fmt.Println("daemon not running: run `bivouac install` once, or `bivouac run` in a terminal")
			}
		} else {
			fmt.Println("daemon not running; the mode is recorded for its next start")
		}
	}
	if wait {
		switch mode {
		case control.ModeOn:
			return e.waitForPhase(ctx, time.Minute, "polling", "maintaining idle pool", "waiting for queued jobs")
		case control.ModeOff:
			return e.waitForPhase(ctx, 3*time.Hour, "exiting")
		default:
			return e.waitForPhase(ctx, 3*time.Hour, "idle")
		}
	}
	return nil
}

func (e env) status(args []string) error {
	var asJSON bool
	if err := parseFlags("status", args, func(fs *flag.FlagSet) { fs.BoolVar(&asJSON, "json", false, "print the raw snapshot") }); err != nil {
		return err
	}
	mode, err := e.files.ReadMode()
	if err != nil {
		return err
	}
	s, err := e.files.ReadStatus()
	if err != nil {
		return err
	}
	if asJSON {
		data, _ := state.ReadFile(filepath.Join(e.layout.State, "status.json"))
		fmt.Println(string(data))
		return nil
	}
	fmt.Print(manager.Describe(s, mode, e.files.Alive()))
	return nil
}

func (e env) install(ctx context.Context) error {
	if err := e.layout.Ensure(); err != nil {
		return err
	}
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		return err
	}
	mode, _ := e.files.ReadMode()
	path, err := install.Install(ctx, install.Paths{Binary: bin, LogDir: e.layout.Logs})
	if err != nil {
		return err
	}
	fmt.Printf("installed %s (mode %s)\n", path, mode)
	if mode != control.ModeOn {
		fmt.Println("the daemon stays idle until `bivouac on`")
	}
	return nil
}

func (e env) uninstall(ctx context.Context) error {
	if err := install.Uninstall(ctx); err != nil {
		return err
	}
	fmt.Println("login item removed; use off/stop to finish or cancel active work; the next run reconciles retained guests")
	return nil
}

func (e env) configCmd(args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "validate":
		path := ""
		if len(args) > 1 {
			path = args[1]
		}
		c, err := e.loadConfig(path)
		if err != nil {
			return err
		}
		fmt.Printf("ok: %d provider(s): %s\n", len(c.Providers), strings.Join(c.ProviderNames(), ", "))
		return nil
	case "example":
		fmt.Print(config.Example)
		return nil
	case "path":
		fmt.Println(e.layout.Config)
		return nil
	}
	return errUsage
}

func (e env) secretCmd(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return errUsage
	}
	store := secret.Default()
	name := args[1]
	switch args[0] {
	case "set":
		var file string
		if err := parseFlags("secret set", args[2:], func(fs *flag.FlagSet) { fs.StringVar(&file, "file", "-", "file to read, or - for stdin") }); err != nil {
			return err
		}
		var r io.Reader = os.Stdin
		if file != "-" {
			f, err := os.Open(file)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			r = f
		}
		data, err := io.ReadAll(bufio.NewReader(r))
		if err != nil {
			return err
		}
		if err := store.Set(ctx, name, data); err != nil {
			return err
		}
		fmt.Printf("stored %q (%d bytes)\n", name, len(data))
		return nil
	case "check":
		v, err := store.Get(ctx, name)
		if err != nil {
			return err
		}
		kind := "value"
		if strings.Contains(string(v), "PRIVATE KEY") {
			kind = "PEM private key"
		}
		fmt.Printf("%q present: %s, %d bytes\n", name, kind, len(v))
		return nil
	case "delete":
		if err := store.Delete(ctx, name); err != nil {
			return err
		}
		fmt.Printf("deleted %q\n", name)
		return nil
	}
	return errUsage
}

// vzCmd imports baselines, and inspects and cleans up macOS guests through
// the provider with the same ownership checks the daemon uses.
func (e env) vzCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	if args[0] == "import" {
		return e.vzImport(args[1:])
	}
	cfg, err := e.loadConfig("")
	if err != nil {
		return err
	}
	if args[0] == "cleanup" {
		// Hold the daemon's lock for the whole command: a daemon starting
		// meanwhile would record and launch guests this sweep calls orphans.
		if err := e.layout.Ensure(); err != nil {
			return err
		}
		lock, err := e.files.Acquire()
		if errors.Is(err, control.ErrAlreadyRunning) {
			return errors.New("the daemon is running; it reconciles orphans itself (use `bivouac status`)")
		}
		if err != nil {
			return err
		}
		defer func() { _ = lock.Release() }()
	}
	store, err := state.Open(e.layout.State, newID)
	if err != nil {
		return err
	}
	providers, err := buildProviders(ctx, cfg, store, e.layout.VMs)
	if err != nil {
		return err
	}
	defer closeProviders(providers)
	known := map[string]bool{}
	for _, inst := range store.List() {
		known[inst.Name] = true
	}
	switch args[0] {
	case "list":
		for _, name := range cfg.ProviderNames() {
			owned, foreign, err := providers[name].List(ctx)
			if err != nil {
				return err
			}
			for _, o := range owned {
				tag := "orphan (no state record)"
				if known[o.Name] {
					tag = "tracked"
				}
				fmt.Printf("%-8s owned    %-40s running=%-5v %s\n", name, o.Name, o.Running, tag)
			}
			for _, f := range foreign {
				tag := "foreign"
				if f.Prefixed {
					tag = "prefixed but not ours (never touched)"
				}
				fmt.Printf("%-8s %-8s %-40s running=%-5v\n", name, tag, f.Name, f.Running)
			}
		}
		return nil
	case "cleanup":
		var dry bool
		if err := parseFlags("vz cleanup", args[1:], func(fs *flag.FlagSet) { fs.BoolVar(&dry, "dry-run", false, "only report") }); err != nil {
			return err
		}
		for _, name := range cfg.ProviderNames() {
			p := providers[name]
			owned, _, err := p.List(ctx)
			if err != nil {
				return err
			}
			for _, o := range owned {
				if known[o.Name] {
					continue
				}
				if dry {
					fmt.Println("would delete", o.Name)
					continue
				}
				if o.Running {
					_ = p.Stop(ctx, o.Name, 30*time.Second)
				}
				if err := p.Delete(ctx, o.Name); err != nil && !errors.Is(err, provider.ErrNotFound) {
					return err
				}
				fmt.Println("deleted", o.Name)
			}
		}
		return nil
	case "run-args":
		for _, name := range cfg.ProviderNames() {
			if tp, ok := providers[name].(*vz.Provider); ok {
				args, err := tp.LaunchArgs("<name>")
				if err != nil {
					return err
				}
				fmt.Printf("%s: bivouac %s\n", name, strings.Join(args, " "))
			}
		}
		return nil
	}
	return errUsage
}

// vzImport copies a Tart-format VM into the VM store as a baseline. The
// operator vouches for the guest: the matching bivouac guest agent is
// installed, the runner is in --runner-dir, and --sudo when the agent's user
// has passwordless sudo.
func (e env) vzImport(args []string) error {
	fs := flag.NewFlagSet("vz import", flag.ContinueOnError)
	runnerDir := fs.String("runner-dir", "", "preinstalled runner in a macOS guest, such as /Users/admin/actions-runner")
	sudo := fs.Bool("sudo", false, "the guest agent's user has passwordless sudo (the release proxy needs it)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 2 {
		return errors.New("usage: bivouac vz import [--runner-dir DIR] [--sudo] <tart-vm-dir> <name>")
	}
	src, name := fs.Arg(0), fs.Arg(1)
	if strings.HasPrefix(name, config.NamePrefix) {
		return fmt.Errorf("baseline names may not start with %q", config.NamePrefix)
	}
	guest := vm.Guest{AgentVersion: guestagent.Version, RunnerDir: *runnerDir, Sudo: *sudo}
	if err := vm.Store(e.layout.VMs).Import(src, name, guest); err != nil {
		return err
	}
	fmt.Printf("imported %s as %q in %s\n", src, name, e.layout.VMs)
	if m, err := vm.ReadManifest(vm.Store(e.layout.VMs).Dir(name)); err == nil {
		if _, err := vz.CheckBaseline(e.layout.VMs, name, m.OS); err != nil {
			fmt.Printf("warning: %v\n", err)
		}
	}
	return nil
}
