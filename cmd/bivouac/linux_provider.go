package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider/crosvm"
	"github.com/GomerPiles/bivouac/internal/state"
)

func buildLinuxProvider(_ context.Context, name string, cfg config.Crosvm, store *state.Store) (*crosvm.Provider, error) {
	opts := crosvm.Options{Name: name, ControllerID: store.ControllerID(), Root: cfg.Root, Binary: cfg.Binary, BinarySHA256: cfg.BinarySHA256, QemuImg: cfg.QemuImg,
		BaselineName: cfg.BaselineName, Baseline: cfg.Baseline, Kernel: cfg.Kernel, KernelSHA256: cfg.KernelSHA256, Initrd: cfg.Initrd, InitrdSHA256: cfg.InitrdSHA256, GPU: cfg.GPU}
	backend, err := crosvm.OpenBackend(opts)
	if err != nil {
		return nil, err
	}
	key, err := linuxGuestKey(cfg.SSHKey)
	if err != nil {
		backend.Close()
		return nil, err
	}
	guest, err := crosvm.NewSSHGuest(crosvm.SSHOptions{StateDir: filepath.Join(filepath.Dir(store.Path()), "crosvm", name), Helper: cfg.Helper, Key: key, User: cfg.User})
	if err != nil {
		backend.Close()
		return nil, err
	}
	p, err := crosvm.New(backend.Options(), backend, guest)
	if err != nil {
		backend.Close()
		return nil, err
	}
	return p, nil
}

// linuxGuestKey keeps the default key already authorized by the Linux baseline
// when ssh_key is omitted. This path is independent of the host VM provider.
func linuxGuestKey(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	if runtime.GOOS != "windows" {
		return "", errors.New("windows guest transport requires Windows")
	}
	base := os.Getenv("ProgramData")
	if base == "" {
		return "", errors.New("ProgramData is unavailable")
	}
	return filepath.Join(base, "AppSandbox", "ssh", "id_appsandbox"), nil
}
