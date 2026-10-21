//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/GomerPiles/bivouac/internal/redact"
	"github.com/GomerPiles/bivouac/internal/vmhost"
	"github.com/GomerPiles/bivouac/internal/winhost"
	"golang.org/x/sys/windows/svc"
)

// vmhostCmd runs or manages the privileged VM host. Only run, service,
// install and uninstall need elevation; start, stop and status use the rights
// the installer granted.
func vmhostCmd(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	fs := flag.NewFlagSet("vmhost "+args[0], flag.ContinueOnError)
	configPath := fs.String("config", "", "administrator-protected VM host configuration")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return errUsage
	}
	switch args[0] {
	case "run":
		cfg, _, err := loadVMHostConfig(*configPath)
		if err != nil {
			return err
		}
		return vmhost.Run(ctx, cfg, slog.New(slog.NewTextHandler(redact.NewWriter(os.Stderr), nil)))
	case "service":
		if is, err := svc.IsWindowsService(); err != nil || !is {
			return errors.New("vmhost service runs only under the service control manager; use vmhost run in a shell")
		}
		cfg, _, err := loadVMHostConfig(*configPath)
		if err != nil {
			return err
		}
		log, closeLog, err := vmhostLog(cfg.Root)
		if err != nil {
			return err
		}
		defer closeLog()
		return vmhost.RunService(cfg, log)
	case "install":
		cfg, abs, err := loadVMHostConfig(*configPath)
		if err != nil {
			return err
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err = vmhost.Install(exe, abs, cfg); err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, "VM host service installed (manual start; bivouac on starts it)")
		return err
	case "uninstall":
		if *configPath != "" {
			return errUsage
		}
		return vmhost.Uninstall()
	case "start", "stop":
		if *configPath != "" {
			return errUsage
		}
		waitCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		if args[0] == "start" {
			return vmhost.StartService(waitCtx)
		}
		return vmhost.StopService(waitCtx)
	case "status":
		if *configPath != "" {
			return errUsage
		}
		return vmhostStatus(ctx, out)
	}
	return errUsage
}

func loadVMHostConfig(path string) (vmhost.Config, string, error) {
	if path == "" {
		return vmhost.Config{}, "", errors.New("--config is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return vmhost.Config{}, "", err
	}
	// Every value bounds unprivileged callers, so none may be user-editable.
	if err = winhost.CheckProtected(abs); err != nil {
		return vmhost.Config{}, "", fmt.Errorf("VM host configuration must be administrator-protected: %w", err)
	}
	f, err := os.Open(abs)
	if err != nil {
		return vmhost.Config{}, "", err
	}
	defer func() { _ = f.Close() }()
	cfg, err := vmhost.DecodeConfig(f)
	return cfg, abs, err
}

// vmhostLog appends redacted structured logs beside the journal. A log over
// 16 MiB at startup is kept as one previous file.
func vmhostLog(root string) (*slog.Logger, func(), error) {
	path := filepath.Join(root, "vmhost.log")
	if info, err := os.Stat(path); err == nil && info.Size() > 16<<20 {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	sink := redact.NewWriter(f)
	return slog.New(slog.NewJSONHandler(sink, nil)), func() { _ = sink.Close(); _ = f.Close() }, nil
}

func vmhostStatus(ctx context.Context, out io.Writer) error {
	installed, state, err := vmhost.ServiceState()
	if err != nil {
		return err
	}
	report := map[string]any{"service_installed": installed}
	if installed {
		report["service_running"] = state == svc.Running
	}
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if info, err := vmhost.NewClient().Info(callCtx); err == nil {
		report["serving"] = true
		report["info"] = info
	} else {
		report["serving"] = false
	}
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	return e.Encode(report)
}
