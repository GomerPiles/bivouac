package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/GomerPiles/bivouac/internal/provider/appsandbox"
	"github.com/GomerPiles/bivouac/internal/secret"
)

// Inspection intentionally bypasses config/state/credential-store setup.
// It neither claims ownership nor makes provider lifecycle calls.
func appsandboxCmd(ctx context.Context, args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "broker" {
		return appsandboxBroker(ctx, args[1:], out)
	}
	if len(args) == 0 || args[0] != "inspect" {
		return errUsage
	}
	var discovery string
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		discovery = filepath.Join(base, "AppSandbox", "host.json")
	}
	fs := flag.NewFlagSet("appsandbox inspect", flag.ContinueOnError)
	fs.StringVar(&discovery, "discovery", discovery, "App Sandbox discovery file (read-only)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return errUsage
	}
	if discovery == "" {
		return errors.New("--discovery is required on this platform")
	}
	c, err := appsandbox.Open(ctx, discovery)
	if err != nil {
		return err
	}
	defer c.Close()
	v, err := c.Version(ctx)
	if err != nil {
		return err
	}
	h, err := c.Host(ctx)
	if err != nil {
		return err
	}
	vms, err := c.List(ctx)
	if err != nil {
		return err
	}
	templates, err := c.Templates(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Version   appsandbox.Version    `json:"version"`
		Host      appsandbox.Host       `json:"host"`
		Foreign   []appsandbox.VM       `json:"foreign_vms"`
		Templates []appsandbox.Template `json:"foreign_templates"`
	}{v, h, vms, templates})
}

// The operator starts this command from an elevated, supported native launch
// context. The command never requests elevation or starts App Sandbox itself.
func appsandboxBroker(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("appsandbox broker", flag.ContinueOnError)
	var configPath, credential string
	fs.StringVar(&configPath, "config", "", "protected broker options JSON")
	fs.StringVar(&credential, "credential", "", "native credential-store item for this broker")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || configPath == "" || credential == "" {
		return errUsage
	}
	// A relative path resolves against the launcher's protected working
	// directory. The options bound the broker independently of the manager,
	// so the file and its ancestors must be writable only by administrators.
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	if err = appsandbox.CheckProtectedFile(configPath); err != nil {
		return fmt.Errorf("broker configuration is not administrator-protected: %w", err)
	}
	f, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 65536 {
		return errors.New("invalid bounded broker configuration file")
	}
	var opts appsandbox.BrokerOptions
	decoder := json.NewDecoder(io.LimitReader(f, 65537))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&opts) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid bounded broker configuration")
	}
	engine, closeEngine, err := appsandbox.OpenNativeEngine(ctx, opts)
	if err != nil {
		return err
	}
	defer closeEngine()
	return appsandbox.ServeBroker(ctx, engine, secret.Default(), credential, out)
}
