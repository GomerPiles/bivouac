package main

import (
	"context"
	"path/filepath"

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
	guest, err := crosvm.NewSSHGuest(crosvm.SSHOptions{StateDir: filepath.Join(filepath.Dir(store.Path()), "crosvm", name), Helper: cfg.Helper, Key: cfg.SSHKey, User: cfg.User})
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
