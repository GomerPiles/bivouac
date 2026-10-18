package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/crosvm"
)

// This explicit local test creates one owned VM, prepares its generic guest,
// and discards it. It never loads GitHub credentials or registers a runner.
func crosvmCmd(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 3 && args[0] == "supervise" && args[1] == "--record" {
		return crosvm.RunSupervisor(ctx, args[2])
	}
	if len(args) == 0 || (args[0] != "validate" && args[0] != "cleanup" && args[0] != "build-image") {
		return errUsage
	}
	fs := flag.NewFlagSet("crosvm validate", flag.ContinueOnError)
	var optionsPath, helper, user, cleanupName, outputRoot string
	var recovery, preparedImage, requirePrepared bool
	var cpu, memoryMB int
	fs.StringVar(&optionsPath, "options", "", "pinned local provider options JSON")
	fs.StringVar(&outputRoot, "output-root", "", "fresh absolute Linux-Images directory for explicit image building")
	fs.StringVar(&helper, "helper", "", "Linux/amd64 guest helper")
	fs.StringVar(&user, "user", "ciuser", "dedicated guest user")
	fs.StringVar(&cleanupName, "name", "", "exact owned validation VM to clean up")
	fs.BoolVar(&requirePrepared, "require-prepared", false, "require exact image helper and DNS reuse in a cold validation")
	fs.BoolVar(&preparedImage, "exercise-prepared-image", false, "test image sanitation and prepared helper/DNS reuse in the owned clone; discard afterwards")
	fs.IntVar(&cpu, "cpu", 2, "isolated trial CPUs (1-4)")
	fs.IntVar(&memoryMB, "memory-mb", 2048, "isolated trial memory (1024-4096 MiB)")
	fs.BoolVar(&recovery, "exercise-recovery", false, "adopt the owned VM and test supervisor-loss cleanup without runner registration")
	if err := fs.Parse(args[1:]); err != nil || cpu < 1 || cpu > 4 || memoryMB < 1024 || memoryMB > 4096 || fs.NArg() != 0 || optionsPath == "" || ((args[0] == "validate" || args[0] == "build-image") && (!filepath.IsAbs(helper) || cleanupName != "")) || args[0] == "build-image" && (!filepath.IsAbs(outputRoot) || filepath.Base(outputRoot) != "Linux-Images" || preparedImage || recovery || requirePrepared) || args[0] != "build-image" && outputRoot != "" || (args[0] == "cleanup" && (cleanupName == "" || helper != "" || recovery || preparedImage)) {
		return errUsage
	}
	absolute, err := filepath.Abs(optionsPath)
	if err != nil {
		return err
	}
	optionsPath = absolute
	f, err := os.Open(optionsPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil || stat.Size() > 65536 {
		return errors.New("invalid bounded native options file")
	}
	var opts crosvm.Options
	decoder := json.NewDecoder(io.LimitReader(f, 65537))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&opts) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid native options JSON")
	}
	backend, err := crosvm.OpenBackend(opts)
	if err != nil {
		return err
	}
	defer backend.Close()
	// Launch checks compare against the canonical paths the backend froze.
	opts = backend.Options()
	sshDir := filepath.Join(filepath.Dir(optionsPath), "ssh")
	if args[0] == "cleanup" {
		cleanCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		for {
			if err := backend.Delete(cleanCtx, cleanupName); err == nil {
				if err := crosvm.ForgetHostKeys(sshDir, cleanupName[strings.LastIndexByte(cleanupName, '-')+1:]); err != nil {
					return err
				}
				_, err = io.WriteString(out, "Recorded native process group and disposable disk confirmed absent\n")
				return err
			}
			select {
			case <-cleanCtx.Done():
				return errors.New("owned cleanup unconfirmed; records retained")
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
	guest, err := crosvm.NewSSHGuest(crosvm.SSHOptions{StateDir: sshDir, Helper: helper, User: user, RequirePrepared: requirePrepared})
	if err != nil {
		return err
	}
	p, err := crosvm.New(opts, backend, guest)
	if err != nil {
		return err
	}
	var idBytes [4]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(idBytes[:])
	name := "bivouac-" + opts.Name + "-" + id
	spec := provider.Spec{Name: name, Baseline: opts.BaselineName, CPU: cpu, MemoryMB: memoryMB, Meta: provider.Metadata{ControllerID: opts.ControllerID, InstanceID: id, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
	defer cancel()
	cleanup := func() error {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		for {
			if err := p.Delete(cleanCtx, name); err == nil {
				return nil
			}
			select {
			case <-cleanCtx.Done():
				return errors.New("owned Linux cleanup remains incomplete; reservation retained")
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
	// This standalone trial never takes capacity from the installed manager.
	// Refuse admission under pressure and cancel only this owned trial on reserve loss.
	sample, err := perf.NewSampler(opts.Root).Sample()
	if err != nil || sample.AvailableBytes < uint64(memoryMB)*(1<<20)+(10<<30) || sample.Commit == nil || sample.Commit.HeadroomBytes() < uint64(memoryMB)*(1<<20)+(4<<30) {
		return errors.New("insufficient host reserves for isolated Linux validation")
	}
	guarded, stopGuard := context.WithCancel(ctx)
	defer stopGuard()
	guardDone := make(chan struct{})
	go func() {
		defer close(guardDone)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-guarded.Done():
				return
			case <-ticker.C:
				s, e := perf.NewSampler(opts.Root).Sample()
				if e != nil || s.AvailableBytes < 6<<30 || s.Commit == nil || s.Commit.HeadroomBytes() < 2<<30 {
					stopGuard()
					return
				}
			}
		}
	}()
	defer func() { stopGuard(); <-guardDone }()
	ctx = guarded
	if err := p.Create(ctx, spec); err != nil {
		return err
	}
	if err := p.Start(ctx, name, out); err != nil {
		return errors.Join(err, cleanup())
	}
	if err := p.WaitReady(ctx, name); err != nil {
		return errors.Join(err, cleanup())
	}
	if _, err := io.WriteString(out, "Owned Linux guest, runner baseline, GPU/CDI and network policy ready; no runner registered\n"); err != nil {
		return errors.Join(err, cleanup())
	}
	status, err := p.RunnerStatus(ctx, name)
	if err != nil {
		return errors.Join(err, cleanup())
	}
	if status.State != provider.RunnerAbsent {
		return errors.Join(errors.New("baseline listener is not absent"), cleanup())
	}

	if args[0] == "build-image" {
		record, e := backend.WaitReady(ctx, name)
		if e != nil {
			return errors.Join(e, cleanup())
		}
		if e = backend.Verify(ctx, name); e != nil {
			return errors.Join(e, cleanup())
		}
		if e = guest.PrepareImageAndShutdown(ctx, record); e != nil {
			return errors.Join(e, cleanup())
		}
		if e = backend.RecordImageShutdown(name, guest.HelperSHA256()); e != nil {
			return errors.Join(e, cleanup())
		}
		image, e := backend.CaptureRawImage(ctx, name, outputRoot, guest.HelperSHA256())
		cleanupErr := cleanup()
		if e != nil || cleanupErr != nil {
			return errors.Join(e, cleanupErr)
		}
		return json.NewEncoder(out).Encode(map[string]any{"image_built": true, "native_absent": true, "source_cleaned": true, "image": image, "helper_sha256": guest.HelperSHA256()})
	}
	if preparedImage {
		record, e := backend.WaitReady(ctx, name)
		if e != nil {
			return errors.Join(e, cleanup())
		}
		if e = backend.Verify(ctx, name); e != nil {
			return errors.Join(e, cleanup())
		}
		if e = guest.ExercisePreparedImage(ctx, record); e != nil {
			return errors.Join(e, cleanup())
		}
		_, _ = io.WriteString(out, "Owned clone image sanitation and prepared helper/DNS reuse passed; no image published\n")
	}
	record, e := backend.WaitReady(ctx, name)
	if e != nil {
		return errors.Join(e, cleanup())
	}
	if e = backend.Verify(ctx, name); e != nil {
		return errors.Join(e, cleanup())
	}
	boot, e := guest.BootReport(ctx, record)
	if e != nil {
		return errors.Join(e, cleanup())
	}
	identities, e := guest.CloneIdentity(ctx, record)
	if e != nil {
		return errors.Join(e, cleanup())
	}
	if e = json.NewEncoder(out).Encode(map[string]any{"boot_timestamps_us": boot, "clone_identity": identities}); e != nil {
		return errors.Join(e, cleanup())
	}
	if recovery {
		backend.Close()
		backend, err = crosvm.OpenBackend(opts)
		if err != nil {
			return errors.Join(err, cleanup())
		}
		defer backend.Close()
		p, err = crosvm.New(opts, backend, guest)
		if err != nil {
			return err
		}
		if err := backend.Verify(ctx, name); err != nil {
			return errors.Join(err, cleanup())
		}
		if err := backend.ExerciseSupervisorLoss(ctx, name); err != nil {
			return errors.Join(err, cleanup())
		}
		_, _ = io.WriteString(out, "Reopened provider adopted the owned live VM; testing recorded supervisor loss\n")
	}
	if err := cleanup(); err != nil {
		return err
	}
	_, err = io.WriteString(out, "Owned Linux native processes and overlay confirmed absent\n")
	return err
}
