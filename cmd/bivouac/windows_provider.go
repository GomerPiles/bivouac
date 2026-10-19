package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider/appsandbox"
	"github.com/GomerPiles/bivouac/internal/secret"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/winhost"
)

func buildWindowsProvider(ctx context.Context, name string, cfg config.AppSandbox, store *state.Store) (*appsandbox.Provider, error) {
	ssh, scp, err := winhost.OpenSSH()
	if err != nil {
		return nil, err
	}
	key := cfg.SSHKey
	if key == "" {
		if key, err = appsandbox.DefaultSSHKey(); err != nil {
			return nil, err
		}
	}
	broker, err := appsandbox.OpenBroker(ctx, secret.Default(), cfg.BrokerSecret, store.ControllerID())
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*appsandbox.Provider, error) { broker.Close(); return nil, err }
	info := broker.Info()
	if info.Baseline != cfg.Baseline || cfg.CPU > info.MaxCPU || cfg.MemoryGB*1024 > info.MaxMemoryMB || cfg.DiskGB > info.MaxDiskGB || info.MaxInstances < 1 {
		return fail(errors.New("provider configuration differs from protected broker bounds"))
	}
	helper, err := os.Executable()
	if err != nil {
		return fail(err)
	}
	guest, err := appsandbox.NewSSHGuest(appsandbox.GuestOptions{
		StateDir:  filepath.Join(filepath.Dir(store.Path()), "appsandbox", name),
		SSHBinary: ssh, SCPBinary: scp, SSHKey: key, Helper: helper,
		RunnerDir: cfg.RunnerDir, RunnerArchive: cfg.RunnerArchive, RunnerSHA256: cfg.RunnerSHA256,
	}, nil)
	if err != nil {
		return fail(err)
	}
	p, err := appsandbox.New(appsandbox.Options{Name: name, Root: info.Root, ControllerID: store.ControllerID(), DiskGB: cfg.DiskGB, GPU: cfg.GPU, HostLimit: info.MaxInstances}, broker, guest)
	if err != nil {
		return fail(err)
	}
	return p, nil
}
