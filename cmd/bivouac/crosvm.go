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
	var reserves crosvmTrialReserves
	fs.StringVar(&optionsPath, "options", "", "pinned local provider options JSON")
	fs.StringVar(&outputRoot, "output-root", "", "fresh absolute Linux-Images directory for explicit image building")
	fs.StringVar(&helper, "helper", "", "Linux/amd64 guest helper")
	fs.StringVar(&user, "user", "ciuser", "dedicated guest user")
	fs.StringVar(&cleanupName, "name", "", "exact owned validation VM to clean up")
	fs.BoolVar(&requirePrepared, "require-prepared", false, "require exact image helper and DNS reuse in a cold validation")
	fs.BoolVar(&preparedImage, "exercise-prepared-image", false, "test image sanitation and prepared helper/DNS reuse in the owned clone; discard afterwards")
	fs.IntVar(&cpu, "cpu", 2, "isolated trial CPUs (1-4)")
	fs.IntVar(&memoryMB, "memory-mb", 2048, "isolated trial memory (1024-4096 MiB)")
	fs.Uint64Var(&reserves.memoryMB, "reserve-memory-mb", 6144, "physical memory to leave available during the isolated trial (MiB)")
	fs.Uint64Var(&reserves.commitMB, "reserve-commit-mb", 2048, "commit headroom to leave during the isolated trial (MiB)")
	fs.BoolVar(&recovery, "exercise-recovery", false, "adopt the owned VM and test supervisor-loss cleanup without runner registration")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || optionsPath == "" {
		return errUsage
	}
	switch args[0] {
	case "validate":
		if !filepath.IsAbs(helper) || cleanupName != "" || outputRoot != "" {
			return errUsage
		}
	case "build-image":
		if !filepath.IsAbs(helper) || cleanupName != "" || !filepath.IsAbs(outputRoot) || filepath.Base(outputRoot) != "Linux-Images" || preparedImage || recovery || requirePrepared {
			return errUsage
		}
	case "cleanup":
		if cleanupName == "" || helper != "" || outputRoot != "" || recovery || preparedImage || requirePrepared {
			return errUsage
		}
	}
	if cpu < 1 || cpu > 4 || memoryMB < 1024 || memoryMB > 4096 || !reserves.valid() {
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
	key, err := linuxGuestKey("")
	if err != nil {
		return err
	}
	guest, err := crosvm.NewSSHGuest(crosvm.SSHOptions{StateDir: sshDir, Helper: helper, Key: key, User: user, RequirePrepared: requirePrepared})
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
	if err != nil || !reserves.allows(sample, uint64(memoryMB)) {
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
				if e != nil || !reserves.allows(s, 0) {
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
	record, e := backend.WaitReady(ctx, name)
	if e != nil {
		return errors.Join(e, cleanup())
	}
	if e = backend.Verify(ctx, name); e != nil {
		return errors.Join(e, cleanup())
	}
	if e = validateCrosvmGuest(ctx, guest, record, preparedImage, out); e != nil {
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

// Standalone trials do not load the installed manager's admission policy.
// Reserve the requested guest allocation before launch; watch the same floors
// after launch. Keep this policy local to the explicit validation/factory CLI.
type crosvmTrialReserves struct{ memoryMB, commitMB uint64 }

func (r crosvmTrialReserves) valid() bool {
	return r.memoryMB > 0 && r.memoryMB <= 1<<20 && r.commitMB > 0 && r.commitMB <= 1<<20
}

func (r crosvmTrialReserves) allows(s perf.Sample, guestMemoryMB uint64) bool {
	return s.AvailableBytes >= (r.memoryMB+guestMemoryMB)*(1<<20) &&
		s.Commit != nil && s.Commit.HeadroomBytes() >= (r.commitMB+guestMemoryMB)*(1<<20)
}

type crosvmValidationGuest interface {
	ExercisePreparedImage(context.Context, crosvm.Record) error
	BootReport(context.Context, crosvm.Record) (map[string]uint64, error)
	CloneIdentity(context.Context, crosvm.Record) (map[string]string, error)
}

func validateCrosvmGuest(ctx context.Context, guest crosvmValidationGuest, record crosvm.Record, preparedImage bool, out io.Writer) error {
	if preparedImage {
		if err := guest.ExercisePreparedImage(ctx, record); err != nil {
			return err
		}
		// Sanitation has cleared machine-id and removed SSH host keys. Only a
		// fresh cold boot can prove identity renewal; this clone is discarded.
		_, err := io.WriteString(out, "Owned clone image sanitation and prepared helper/DNS reuse passed; no image published\n")
		return err
	}
	boot, err := guest.BootReport(ctx, record)
	if err != nil {
		return err
	}
	identities, err := guest.CloneIdentity(ctx, record)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{"boot_timestamps_us": boot, "clone_identity": identities})
}
