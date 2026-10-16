//go:build windows

package hcsspike

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/provider/appsandbox"
	"golang.org/x/sys/windows"
)

func RunCLI(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 1 && args[0] == "check" {
		result, err := Check()
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(result)
	}
	if len(args) == 0 || (args[0] != "plan" && args[0] != "headroom" && args[0] != "trial" && args[0] != "cleanup") {
		return errors.New("usage: hcs-spike check | plan|headroom|trial|cleanup --config <file>")
	}
	fs := flag.NewFlagSet("hcs-spike", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "spike configuration JSON")
	retainFailed := fs.Bool("retain-failed-storage", false, "retain stopped failed-trial storage for explicit offline inspection")
	bootOnly := fs.Bool("boot-only", false, "test native lifecycle without guest initialization")
	if fs.Parse(args[1:]) != nil || *path == "" || fs.NArg() != 0 || ((*bootOnly || *retainFailed) && args[0] != "trial") {
		return errors.New("provide --config <file>; --boot-only and --retain-failed-storage are valid only for trial")
	}
	// Refuse before reading configuration or creating any file. Never prompt,
	// invoke runas, install a service/task, or use the existing elevated broker.
	live := args[0] == "trial" || args[0] == "cleanup"
	if live && !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("live HCS spike requires an explicitly elevated launch; no elevation was requested and no VM was touched")
	}
	if live {
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return err
		}
		if err = appsandbox.CheckProtectedFile(absolute); err != nil {
			return errors.New("live spike configuration must be administrator-protected")
		}
	}
	f, err := os.Open(*path)
	if err != nil {
		return errors.New("cannot open spike configuration")
	}
	c, err := DecodeConfig(f)
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if args[0] == "plan" {
		plan, err := Plan(c)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	}
	if args[0] == "headroom" {
		report, err := Headroom(c)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report)
	}
	// Refuse before opening the journal or hashing the immutable template.
	// Native preparation and dispatch recheck after potentially slow staging.
	// Cleanup remains available regardless of host pressure.
	if args[0] == "trial" {
		if err = requireHeadroom(c); err != nil {
			return err
		}
	}
	if err = appsandbox.CheckProtectedFile(c.Root); err != nil {
		return errors.New("create a separate administrator-protected HCS-Spike directory before a live trial")
	}
	lock, err := (control.Files{Dir: c.Root}).Acquire()
	if err != nil {
		return errors.New("spike root is already locked or inaccessible")
	}
	defer func() { _ = lock.Release() }()
	j, err := openJournal(c.Root)
	if err != nil {
		return err
	}
	defer func() { _ = j.root.Close() }()
	api := &native{dll: windows.NewLazySystemDLL("computecore.dll")}
	if err = api.check(); err != nil {
		return err
	}
	if args[0] == "cleanup" {
		cleanupCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		if err = cleanup(cleanupCtx, c, j, api); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(Report{Cleaned: true, NativeAbsent: true})
	}
	baseline, err := pinBaseline(c)
	if err != nil {
		return err
	}
	defer func() { _ = baseline.Close() }()
	trialCtx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds+120)*time.Second)
	defer cancel()
	report, trialErr := guardTrialResources(trialCtx, c, func(guarded context.Context) (Report, error) {
		return trial(guarded, c, j, api, *bootOnly, *retainFailed)
	})
	if err = json.NewEncoder(out).Encode(report); err != nil {
		return errors.Join(trialErr, fmt.Errorf("write spike report: %w", err))
	}
	return trialErr
}
