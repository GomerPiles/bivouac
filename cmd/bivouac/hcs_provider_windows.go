//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/hcsvm"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/vmhost"
	"golang.org/x/sys/windows/svc"
)

// buildHCSProvider does not contact the VM host: the manager may start
// before it, for example while CI is off and the service is stopped.
func buildHCSProvider(name string, cfg config.HCS, store *state.Store) (provider.Provider, error) {
	helper, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return hcsvm.New(hcsvm.Options{
		Service: vmHostService{},
		Name:    name, ControllerID: store.ControllerID(), Image: cfg.Image, GuestName: cfg.GuestName, GuestUser: cfg.GuestUser,
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
	check := hcsvm.Options{Image: cfg.Image, CPU: uint32(cfg.CPU), MemoryMB: uint64(cfg.MemoryGB) * 1024} // #nosec G115 -- config bounds CPU and memory.
	_, err := check.CheckVMHost(callCtx, vmhost.NewClient())
	return err
}

type vmHostService struct{}

func (vmHostService) State(ctx context.Context) (bool, svc.State, error) {
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	return vmhost.ServiceState()
}

func (vmHostService) Start(ctx context.Context) error { return vmhost.StartService(ctx) }
func (vmHostService) Stop(ctx context.Context) error  { return vmhost.StopService(ctx) }

func (e env) printHCSOff() {
	cfg, err := config.Load(e.layout.Config)
	if err != nil {
		return
	}
	for _, p := range cfg.Providers {
		if p.Type == "hcs" {
			fmt.Println("the VM host service stops too once it has no guests; a foreground host stays running")
			return
		}
	}
}
