package vzbuild

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/linuxguest"
	"github.com/GomerPiles/bivouac/internal/provider/vz"
	"github.com/GomerPiles/bivouac/internal/redact"
	"github.com/GomerPiles/bivouac/internal/vm"
	"github.com/GomerPiles/bivouac/internal/vzrecipe"
	"golang.org/x/sys/unix"
)

// Build is an explicit host factory operation; it is never called by a daemon.
func Build(ctx context.Context, o Options) (result error) {
	r, diskBytes, err := o.prepare()
	if err != nil {
		return err
	}
	if err := o.Layout.Ensure(); err != nil {
		return err
	}
	f, err := openFactory(o.Layout.VMs, control.Files{Dir: o.Layout.State})
	if err != nil {
		return err
	}
	defer func() { _ = f.lock.Close() }()
	f.logs = o.Layout.Logs
	if err = f.recover(ctx); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = f.recoverInputs(o.Layout.BaselineInputs); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(redact.NewWriter(os.Stderr), nil))
	for _, warning := range f.warnings {
		log.Warn("factory recovery retained state", "reason", warning)
	}
	f.archived = nil // prior recovered logs do not belong to the new build
	if err = f.advisoryTarget(o.Name, o.Replace); err != nil {
		return err
	}

	if err = (vz.GuestRuntime{OS: "linux", Helper: o.Helper}).CheckHelper(); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err = vm.CheckEntitlement(ctx, exe); err != nil {
		return err
	}
	if err = vz.CheckIsolation(ctx); err != nil {
		return err
	}
	// Disks are sparse and the gate is an APFS clone, so one fully allocated
	// target disk bounds what the guests can write. Add both pinned inputs,
	// a bounded helper/seed copy, and 1 GiB reserve. The factory does not
	// borrow the daemon's resource budget.
	//nolint:gosec // diskBytes and recipe input sizes are positive and bounded below 1 TiB in total.
	required := uint64(diskBytes + r.Source.Size + 2*r.Runner.Size + (128 << 20) + (1 << 30))
	var space unix.Statfs_t
	if err = unix.Statfs(string(f.store), &space); err != nil {
		return err
	}
	if space.Bsize <= 0 || space.Bavail < required/uint64(space.Bsize)+1 {
		return errors.New("insufficient free space: reserve one target disk, pinned inputs, seed and 1 GiB headroom")
	}
	client := inputClient()
	defer client.CloseIdleConnections()
	image, err := obtain(ctx, o.Layout.BaselineInputs, o.Image, r.Source, client)
	if err != nil {
		return err
	}
	runner, err := obtain(ctx, o.Layout.BaselineInputs, o.RunnerArchive, r.Runner, client)
	if err != nil {
		return err
	}
	helperDigest, err := linuxguest.HelperSHA256(o.Helper)
	if err != nil {
		return err
	}
	hostDigest, err := hashHostExecutable(exe)
	if err != nil {
		return err
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return err
	}
	rec := factoryRecord{Owner: factoryOwner, ID: hex.EncodeToString(id[:]), Recipe: r.Name, Target: o.Name, Phase: "staging", BuildDir: ".build-" + hex.EncodeToString(id[:]), GateDir: ".gate-" + hex.EncodeToString(id[:])}
	if err = writeRecord(f.dir, rec); err != nil {
		return err
	}
	complete := false
	defer func() {
		if complete {
			return
		}
		// Cleanup uses persisted evidence, including swap intent when publication
		// failed halfway. A cleanup error retains the journal for the next build.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		saved, err := readRecord(filepath.Join(f.dir, rec.ID+".json"))
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err == nil {
			err = f.recoverRecord(cleanupCtx, saved)
		}
		for _, archived := range f.archived {
			result = fmt.Errorf("%w; factory launch log: %s", result, archived)
		}

		result = errors.Join(result, err)
	}()
	buildName, gateName := rec.BuildDir, rec.GateDir
	buildDir := f.store.Dir(buildName)
	if err = os.Mkdir(buildDir, 0700); err != nil {
		return err
	}
	rec.Build, err = fileIdentity(buildDir)
	if err != nil {
		return err
	}
	if err = writeRecord(f.dir, rec); err != nil {
		return err
	}
	if _, err = convert(ctx, image, filepath.Join(buildDir, vm.DiskFile), diskBytes); err != nil {
		return err
	}
	if err = vm.CreateEFIStore(filepath.Join(buildDir, vm.NVRAMFile)); err != nil {
		return err
	}
	manifest, err := vm.NewLinuxManifest(o.CPU, o.MemoryGB)
	if err != nil {
		return err
	}
	if err = vm.WriteManifest(buildDir, manifest); err != nil {
		return err
	}
	if err = writeSeed(buildDir, r, o.Helper, helperDigest, runner); err != nil {
		return err
	}
	receipt := filepath.Join(buildDir, "receipt.img")
	if err = writeReceipt(receipt); err != nil {
		return err
	}
	rec.Phase = "provisioning"
	if err = writeRecord(f.dir, rec); err != nil {
		return err
	}
	provisionCtx, cancel := context.WithTimeout(ctx, r.ProvisionTimeout)
	opts := vm.RunOptions{Dir: buildDir, AgentPort: guestagent.Port, RootlessNetwork: true, Network: o.Network, Machine: vm.MachineOptions{SeedDisk: filepath.Join(buildDir, "seed.iso"), ReceiptDisk: receipt, DiskSync: "full"}}
	opts.AgentSocket, err = f.store.SocketPath(buildName)
	if err == nil {
		err = provisionVM(provisionCtx, exe, opts)
	}
	cancel()
	if err != nil {
		return err
	}
	receiptFile, err := os.Open(receipt)
	if err != nil {
		return err
	}
	err = readReceipt(receiptFile, helperDigest)
	_ = receiptFile.Close()
	if err != nil {
		return err
	}
	for _, name := range []string{vm.NVRAMFile, "seed.iso", "receipt.img", "launch.log"} {
		if err = os.Remove(filepath.Join(buildDir, name)); err != nil {
			return err
		}
	}
	if err = vm.CreateEFIStore(filepath.Join(buildDir, vm.NVRAMFile)); err != nil {
		return err
	}
	manifest.Build = &vm.Build{Recipe: r.Name, SourceURL: r.Source.URLs[0], SourceSHA256: r.Source.SHA256, RunnerURL: r.Runner.URLs[0], RunnerSHA256: r.Runner.SHA256, HelperSHA256: helperDigest, HostSHA256: hostDigest, DiskBytes: diskBytes}
	if err = vm.WriteManifest(buildDir, manifest); err != nil {
		return err
	}
	if err = syncVM(buildDir); err != nil {
		return err
	}
	rec.Phase = "prepared"
	if err = writeRecord(f.dir, rec); err != nil {
		return err
	}
	// Both factory names were journaled before creation. Recovery can recognize
	// an interrupted clone by its recorded identity or expected regular files.
	if err = f.store.CloneFactory(buildName, gateName); err != nil {
		if gateID, idErr := fileIdentity(f.store.Dir(gateName)); idErr == nil {
			rec.Gate = gateID
			_ = writeRecord(f.dir, rec)
		}
		return err
	}
	rec.Gate, err = fileIdentity(f.store.Dir(gateName))
	if err != nil {
		return err
	}
	rec.Phase = "gate"
	if err = writeRecord(f.dir, rec); err != nil {
		return err
	}
	gateCtx, gateCancel := context.WithTimeout(ctx, r.GateTimeout)
	err = coldGate(gateCtx, f, exe, gateName, rec, helperDigest, diskBytes, o.Network)
	gateCancel()
	if err != nil {
		return err
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = f.removeVM(cleanupCtx, gateName, rec.Gate, false)
	cleanupCancel()
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = syncVM(buildDir); err != nil {
		return err
	}
	if err = f.publish(&rec, o.Replace); err != nil {
		return err
	}
	complete = true
	return nil
}
func writeReceipt(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err = f.Write(make([]byte, receiptSize)); err != nil {
		return err
	}
	return f.Sync()
}
func hashHostExecutable(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot fingerprint host executable")
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 512<<20+1))
	if err != nil || n > 512<<20 {
		return "", errors.New("host executable exceeds fingerprint bound")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func writeSeed(dir string, r vzrecipe.Recipe, helper, helperHash, runner string) error {
	helperFile, err := os.Open(helper)
	if err != nil {
		return err
	}
	defer func() { _ = helperFile.Close() }()
	helperStat, err := helperFile.Stat()
	if err != nil || helperStat.Size() > 128<<20 {
		return errors.New("invalid bounded seed helper")
	}
	runnerFile, err := os.Open(runner)
	if err != nil {
		return err
	}
	defer func() { _ = runnerFile.Close() }()
	// Hash the exact bytes streamed into the ISO, catching a changed source file.
	hh, rh := sha256.New(), sha256.New()
	files, err := seedFiles(r, ISOFile{Size: helperStat.Size(), Reader: io.TeeReader(helperFile, hh)}, ISOFile{Size: r.Runner.Size, Reader: io.TeeReader(runnerFile, rh)})
	if err != nil {
		return err
	}
	out, err := os.OpenFile(filepath.Join(dir, "seed.iso"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	if err = WriteISO(out, files); err != nil {
		return err
	}
	if hex.EncodeToString(hh.Sum(nil)) != helperHash || hex.EncodeToString(rh.Sum(nil)) != r.Runner.SHA256 {
		return errors.New("seed inputs changed during construction")
	}
	return out.Sync()
}
func syncVM(dir string) error {
	for _, name := range []string{vm.ManifestFile, vm.DiskFile, vm.NVRAMFile} {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR, 0)
		if err != nil {
			return err
		}
		err = errors.Join(f.Sync(), f.Close())
		if err != nil {
			return err
		}
	}
	return syncDir(dir)
}

type buildProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func startVM(ctx context.Context, exe string, opts vm.RunOptions) (*buildProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	log, err := os.OpenFile(filepath.Join(opts.Dir, "launch.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer func() { _ = log.Close() }()
	cmd := exec.Command(exe, append([]string{"vm", "run"}, opts.Args()...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.WaitDelay = 5 * time.Second
	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("cannot launch factory VM helper: %w", err)
	}
	p := &buildProcess{cmd: cmd, done: make(chan struct{})}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	return p, nil
}
func (p *buildProcess) stop() error {
	select {
	case <-p.done:
		return nil
	default:
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-p.done:
		return nil
	case <-time.After(10 * time.Second):
	}
	if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-p.done:
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("factory helper did not exit after kill")
	}
}
func provisionVM(ctx context.Context, exe string, opts vm.RunOptions) error {
	p, err := startVM(ctx, exe, opts)
	if err != nil {
		return err
	}
	return requireProvisionExit(ctx, p.done, func() error { return p.err }, p.stop)
}
