package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/hostinfo"
	"github.com/GomerPiles/bivouac/internal/manager"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/vz"
	"github.com/GomerPiles/bivouac/internal/redact"
	"github.com/GomerPiles/bivouac/internal/secret"
	"github.com/GomerPiles/bivouac/internal/state"
)

// run is the foreground daemon. launchd runs the same thing.
func (e env) run(ctx context.Context, args []string) error {
	if err := parseFlags("run", args, func(*flagSet) {}); err != nil {
		return err
	}
	if err := e.layout.Ensure(); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(e.layout.Logs, "bivouac.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = logFile.Close() }()
	sinks := []io.Writer{logFile}
	if fi, err := os.Stderr.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		sinks = append(sinks, os.Stderr)
	}
	sink := redact.NewWriter(io.MultiWriter(sinks...))
	defer func() { _ = sink.Close() }()
	log := slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log.Info("bivouac starting", "version", version(), "pid", os.Getpid(), "config", e.layout.Config)

	lock, err := e.files.Acquire()
	if err != nil {
		if errors.Is(err, control.ErrAlreadyRunning) {
			// launchd or an operator started a second copy; the first one
			// keeps the state. Exit 0 so launchd does not retry in a loop.
			log.Warn("another daemon already runs; exiting", "pid_file", e.layout.State)
			return nil
		}
		return err
	}
	defer func() { _ = lock.Release() }()
	if err := e.files.WritePID(os.Getpid()); err != nil {
		return err
	}
	defer func() { _ = e.files.RemovePID() }()

	fail := func(err error) error {
		log.Error("daemon cannot start", "error", err)
		mode, _ := e.files.ReadMode()
		_ = e.files.WriteStatus(&control.Status{PID: os.Getpid(), Mode: mode, Phase: "error: " + err.Error()})
		// Exit 0 so launchd does not restart in a loop; `doctor` explains.
		return nil
	}

	cfg, err := e.loadConfig("")
	if err != nil {
		return fail(err)
	}
	store, err := state.Open(e.layout.State, newID)
	if err != nil {
		return fail(err)
	}
	gh, jit, err := e.githubClients(ctx, cfg)
	if err != nil {
		return fail(err)
	}
	providers, err := buildProviders(ctx, cfg, store, e.layout.VMs)
	if err != nil {
		return fail(err)
	}
	defer closeProviders(providers)
	// Only the daemon runs guests; list and cleanup work without this.
	for name, p := range providers {
		if r, ok := p.(interface{ CheckRuntime(context.Context) error }); ok {
			if err := r.CheckRuntime(ctx); err != nil {
				return fail(fmt.Errorf("provider %q: %w", name, err))
			}
		}
	}
	var cacheService *cache.Service
	if cfg.Cache.Enabled {
		service, cacheErr := cache.Start(e.layout.Cache, cfg.Cache.Listen, cfg.Cache.GuestHost, cfg.Cache.MaxGB<<30, cfg.Cache.MaxObjectMB<<20, cfg.Budget.JobTimeout.Duration+time.Hour, log)
		if cacheErr == nil && cfg.Cache.ReleaseProxy {
			service.EnableReleaseProxy()
		}
		if cacheErr != nil {
			log.Warn("cache service unavailable; guests use upstream downloads")
		} else {
			cacheService = service
			defer service.Close()
			for _, p := range providers {
				if tp, ok := p.(interface{ SetCache(*cache.Service) }); ok {
					tp.SetCache(service)
				}
			}
		}
	}

	wake := make(chan struct{}, 1)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, control.WakeSignal)
	defer signal.Stop(sigs)
	go func() {
		for range sigs {
			select {
			case wake <- struct{}{}:
			default:
			}
		}
	}()

	m, err := manager.New(manager.Options{
		Config: cfg, Store: store, Files: e.files, Providers: providers, GitHub: gh, JIT: jit,
		Host: hostinfo.Get(), Log: log, LogDir: e.layout.Logs, DiagDir: e.layout.Diagnostics,
		Wake: wake, NewID: newID,
		Cache: cacheService,
	})
	if err != nil {
		return fail(err)
	}
	err = m.Run(ctx)
	if errors.Is(err, manager.ErrRefused) {
		// A restart cannot help: report it in status and exit cleanly.
		return fail(err)
	}
	log.Info("bivouac stopped", "error", err)
	return err
}

func (e env) githubClients(ctx context.Context, cfg *config.Config) (github.ScaleSets, github.JITRunners, error) {
	key, err := secret.Default().Get(ctx, cfg.GitHub.PrivateKeySecret)
	if err != nil {
		return nil, nil, fmt.Errorf("credential store item %q: %w", cfg.GitHub.PrivateKeySecret, err)
	}
	auth := github.AppAuth{ClientID: cfg.GitHub.AppClientID, InstallationID: cfg.GitHub.AppInstallationID, PrivateKeyPEM: key}
	if cfg.GitHub.Demand == config.DemandJIT {
		c, err := github.NewJITClient(cfg.GitHub.URL, auth, version())
		return nil, c, err
	}
	c, err := github.NewClient(cfg.GitHub.URL, auth, version())
	return c, nil, err
}

func buildProviders(ctx context.Context, cfg *config.Config, store *state.Store, vms string) (map[string]provider.Provider, error) {
	out := map[string]provider.Provider{}
	for name, p := range cfg.Providers {
		switch p.Type {
		case "crosvm":
			lp, err := buildLinuxProvider(ctx, name, *p.Crosvm, store)
			if err != nil {
				closeProviders(out)
				return nil, err
			}
			out[name] = lp
		case "appsandbox":
			wp, err := buildWindowsProvider(ctx, name, *p.AppSandbox, store)
			if err != nil {
				closeProviders(out)
				return nil, err
			}
			out[name] = wp
		case "vz":
			tp, err := vz.New(name, *p.VZ, store.ControllerID(), vms, nil)
			if err != nil {
				closeProviders(out)
				return nil, err
			}
			out[name] = tp
			tp.SetRecords(store)
		default:
			closeProviders(out)
			return nil, fmt.Errorf("provider %q: type %q not implemented on this host", name, p.Type)
		}
	}
	return out, nil
}

func closeProviders(providers map[string]provider.Provider) {
	for _, p := range providers {
		if closer, ok := p.(interface{ Close() }); ok {
			closer.Close()
		}
	}
}

// waitForPhase blocks until the status snapshot reports one of the phases.
func (e env) waitForPhase(ctx context.Context, timeout time.Duration, phases ...string) error {
	deadline := time.Now().Add(timeout)
	for {
		s, err := e.files.ReadStatus()
		if err != nil {
			return err
		}
		if s != nil {
			for _, p := range phases {
				if s.Phase == p {
					return nil
				}
			}
		}
		if !e.files.Alive() {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for the daemon")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}
