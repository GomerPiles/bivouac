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

	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/crosvm"
)

// This explicit local test creates one owned VM, prepares its generic guest,
// and discards it. It never loads GitHub credentials or registers a runner.
func crosvmCmd(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 3 && args[0] == "supervise" && args[1] == "--record" {
		return crosvm.RunSupervisor(ctx, args[2])
	}
	if len(args) == 0 || (args[0] != "validate" && args[0] != "cleanup") {
		return errUsage
	}
	fs := flag.NewFlagSet("crosvm validate", flag.ContinueOnError)
	var optionsPath, helper, user, cleanupName string
	var recovery bool
	fs.StringVar(&optionsPath, "options", "", "pinned local provider options JSON")
	fs.StringVar(&helper, "helper", "", "Linux/amd64 guest helper")
	fs.StringVar(&user, "user", "ciuser", "dedicated guest user")
	fs.StringVar(&cleanupName, "name", "", "exact owned validation VM to clean up")
	fs.BoolVar(&recovery, "exercise-recovery", false, "adopt the owned VM and test supervisor-loss cleanup without runner registration")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || optionsPath == "" || (args[0] == "validate" && (!filepath.IsAbs(helper) || cleanupName != "")) || (args[0] == "cleanup" && (cleanupName == "" || helper != "" || recovery)) {
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
	guest, err := crosvm.NewSSHGuest(crosvm.SSHOptions{StateDir: sshDir, Helper: helper, User: user})
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
	spec := provider.Spec{Name: name, Baseline: opts.BaselineName, CPU: 4, MemoryMB: 4096, Meta: provider.Metadata{ControllerID: opts.ControllerID, InstanceID: id, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
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
