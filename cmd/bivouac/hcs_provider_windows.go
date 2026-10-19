//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/hcsvm"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/vmhost"
)

// buildHCSProvider does not contact the VM host: the manager may start
// before it, for example while CI is off and the service is stopped.
func buildHCSProvider(name string, cfg config.HCS, store *state.Store) (provider.Provider, error) {
	helper, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return hcsvm.New(hcsvm.Options{
		Name: name, ControllerID: store.ControllerID(), Image: cfg.Image, GuestName: cfg.GuestName, GuestUser: cfg.GuestUser,
		CPU: uint32(cfg.CPU), MemoryMB: uint64(cfg.MemoryGB) * 1024, LazyMemory: cfg.LazyMemory, GPU: cfg.GPU, // #nosec G115 -- config bounds CPU to 1-64 and memory to 1-256 GiB.
		RunnerDir: cfg.RunnerDir, RunnerArchive: cfg.RunnerArchive, RunnerSHA256: cfg.RunnerSHA256,
		Helper: helper, StateDir: filepath.Join(filepath.Dir(store.Path()), "hcs", name),
	}, vmhost.NewClient(), hcsvm.NewTransport(cfg.GuestUser))
}

// checkVMHost reports whether the running VM host serves this provider's
// image within its limits. It creates nothing.
func checkVMHost(ctx context.Context, cfg config.HCS) error {
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	info, err := vmhost.NewClient().Info(callCtx)
	if err != nil {
		return fmt.Errorf("VM host unavailable (start it with bivouac vmhost start, or run it elevated): %w", err)
	}
	if !slices.Contains(info.Images, cfg.Image) {
		return fmt.Errorf("VM host has no image %q", cfg.Image)
	}
	if uint32(cfg.CPU) > info.MaxCPU || uint64(cfg.MemoryGB)*1024 > info.MaxMemoryMB { // #nosec G115 -- config bounds CPU and memory.
		return errors.New("guest size exceeds the VM host's limits")
	}
	return nil
}
