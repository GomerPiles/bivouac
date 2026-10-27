package vzbuild

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/linuxguest"
	"github.com/GomerPiles/bivouac/internal/provider/vz"
	"github.com/GomerPiles/bivouac/internal/rootnet"
	"github.com/GomerPiles/bivouac/internal/vm"
)

type gateOutput struct {
	bytes.Buffer
	limit int
}

func (b *gateOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("factory gate output exceeds bound")
	}
	return b.Buffer.Write(p)
}
func coldGate(ctx context.Context, f *factory, exe, name string, rec factoryRecord, hash string, diskBytes int64, network config.VZNetwork) (result error) {
	socket, err := f.store.SocketPath(name)
	if err != nil {
		return err
	}
	opts := vm.RunOptions{Dir: f.store.Dir(name), AgentPort: guestagent.Port, AgentSocket: socket, RootlessNetwork: true, Network: network, Machine: vm.MachineOptions{DiskSync: "full"}}
	p, err := startVM(ctx, exe, opts)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, p.stop()) }()
	exec := func(ctx context.Context, args []string, in io.Reader, limit int) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		saved, err := readRecord(filepath.Join(f.dir, rec.ID+".json"))
		if err != nil || saved != rec {
			return nil, errors.New("factory gate ownership record differs")
		}
		got, err := fileIdentity(opts.Dir)
		if err != nil || got != rec.Gate {
			return nil, errors.New("factory gate directory identity differs")
		}
		select {
		case <-p.done:
			return nil, errors.New("factory gate helper exited")
		default:
		}
		pid, err := vm.HelperPID(opts.Dir)
		// Before the helper claims its manifest, the agent is still unavailable.
		if err != nil {
			return nil, err
		}
		if pid == 0 {
			return nil, guestagent.ErrUnavailable
		}
		if pid != p.cmd.Process.Pid {
			return nil, errors.New("factory gate helper identity differs")
		}
		if err = vm.ProveIsolation(opts.Dir, rootnet.PolicyID); err != nil {
			if len(args) == 1 && args[0] == "true" {
				return nil, guestagent.ErrUnavailable
			}
			return nil, err
		}
		out := &gateOutput{limit: limit}
		if err = guestagent.Run(ctx, guestagent.DialUnix(socket), args, in, out); err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	}
	if err = vz.WaitAgent(ctx, exec, p.done, func() error { return p.err }); err != nil {
		return err
	}
	cfg := linuxguest.GuestConfig{Profile: linuxguest.VZ, Name: "bivouac-factory-" + rec.ID, ControllerID: "factory-" + rec.ID, RunnerDir: "/opt/actions-runner"}
	return vz.CheckLinuxFactoryGate(ctx, exec, cfg, hash, diskBytes)
}
