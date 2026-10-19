//go:build windows

package hcsspike

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/provider/appsandbox"
	"golang.org/x/sys/windows"
)

func RunCLI(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 1 && args[0] == "image-pins" {
		return json.NewEncoder(out).Encode(struct {
			Sanitation string `json:"sanitation_sha256"`
			Validation string `json:"validation_sha256"`
			Autologon  string `json:"autologon_sha256"`
		}{sanitationHash(), validationHash(), autologonHash()})
	}
	if len(args) == 1 && args[0] == "check" {
		result, err := Check()
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(result)
	}
	if len(args) == 0 || (args[0] != "plan" && args[0] != "headroom" && args[0] != "trial" && args[0] != "cleanup" && args[0] != "build-image") {
		return errors.New("usage: hcs-spike check|image-pins | plan|headroom|trial|build-image|cleanup --config <file>")
	}
	fs := flag.NewFlagSet("hcs-spike", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "spike configuration JSON")
	retainFailed := fs.Bool("retain-failed-storage", false, "retain stopped failed-trial storage for explicit offline inspection")
	bootEvents := fs.Bool("boot-events", false, "read fixed guest boot events after validated readiness")
	bootEventLogs := fs.Bool("boot-event-logs", false, "enable task event logging only in a diagnostic image build")
	bootOnly := fs.Bool("boot-only", false, "test native lifecycle without guest initialization")
	repetitions := fs.Int("repetitions", 1, "sequential fresh clones sharing one immutable-image verification")
	instanceID := fs.String("instance-id", "", "matching retained instance identity for cleanup")
	if fs.Parse(args[1:]) != nil || *path == "" || fs.NArg() != 0 || *repetitions < 1 || *repetitions > 5 || (*bootEventLogs && args[0] != "build-image") || (*bootOnly && args[0] != "trial") || (*bootEvents && (args[0] != "trial" || *bootOnly)) || (*retainFailed && args[0] != "trial" && args[0] != "build-image") || (*repetitions != 1 && args[0] != "trial") || (*instanceID != "" && args[0] != "cleanup") {
		return errors.New("provide --config; repetitions 1-5/boot-only require trial; boot-events requires guest trial; boot-event-logs requires build-image; instance-id requires cleanup")
	}
	// Refuse before reading configuration or creating any file. Never prompt,
	// invoke runas, install a service/task, or use the existing elevated broker.
	live := args[0] == "trial" || args[0] == "cleanup" || args[0] == "build-image"
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
	if *instanceID != "" {
		c.InstanceID = *instanceID
		if err = c.Validate(); err != nil {
			return err
		}
	}
	if *bootEvents && c.PreparedImage == nil {
		return errors.New("boot-events requires a prepared-image trial")
	}
	if args[0] == "build-image" && c.ImageRoot == "" {
		return errors.New("build-image requires image_root and complete build assets")
	}
	if args[0] == "trial" && c.ImageRoot != "" {
		return errors.New("image output requires build-image mode")
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
	if args[0] == "trial" || args[0] == "build-image" {
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
	api := &native{dll: windows.NewLazySystemDLL("computecore.dll"), bootEvents: *bootEvents, bootEventLogs: *bootEventLogs}
	if err = api.check(); err != nil {
		return err
	}
	if args[0] == "cleanup" {
		cleanupCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		var existing record
		readErr := j.read(recordName(c), &existing)
		if errors.Is(readErr, os.ErrNotExist) && c.ImageRoot != "" {
			if _, e := j.root.Stat(c.InstanceID); !errors.Is(e, os.ErrNotExist) {
				return errors.New("unrecorded child retained")
			}
			if err = absent(cleanupCtx, api, c.name()); err != nil {
				return err
			}
		} else if err = cleanup(cleanupCtx, c, j, api); err != nil {
			return err
		}
		if err = cleanupImageStaging(c); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(Report{InstanceID: c.InstanceID, Cleaned: true, NativeAbsent: true})
	}
	baselineStarted := time.Now()
	images, err := openImageSession(c)
	if err != nil {
		return err
	}
	defer images.Close()
	baselineMS := elapsedMS(baselineStarted)
	return runTrialSession(ctx, c, *repetitions, func(sessionCtx context.Context, current Config, index int) (Report, error) {
		started := time.Now()
		budget := current.TimeoutSeconds + 120
		if current.ImageRoot != "" {
			budget += 600
		}
		trialCtx, cancel := context.WithTimeout(sessionCtx, time.Duration(budget)*time.Second)
		defer cancel()
		var output *journal
		if current.ImageRoot != "" {
			var e error
			output, e = beginImageOutput(current)
			if e != nil {
				return Report{}, e
			}
			defer func() { _ = output.root.Close() }()
		}
		var beforeTrialMS uint64
		report, trialErr := guardTrialResources(trialCtx, current, func(guarded context.Context) (Report, error) {
			beforeTrialMS = elapsedMS(started)
			r, e := trial(guarded, current, j, api, *bootOnly, *retainFailed)
			if e == nil && output != nil {
				if e = publishImage(guarded, current, j, output, api, &r); e == nil {
					cleanupCtx, done := context.WithTimeout(context.WithoutCancel(guarded), 60*time.Second)
					e = cleanup(cleanupCtx, current, j, api)
					done()
					r.Cleaned = e == nil
					r.StorageRetained = e != nil
				}
			}
			return r, e
		})
		if trialErr != nil && current.ImageRoot != "" && report.NativeAbsent {
			trialErr = errors.Join(trialErr, cleanupImageStaging(current))
		}
		if report.TimingsMS.ToValidatedDesktopMS != 0 {
			report.TimingsMS.ToValidatedDesktopMS += beforeTrialMS
		}
		report.TimingsMS.TotalMS = elapsedMS(started)
		report.TimingsMS.Preparation = api.preparationTimings
		if index == 0 {
			report.TimingsMS.BaselineVerifyMS = baselineMS
			report.TimingsMS.TotalMS += baselineMS
			if report.TimingsMS.ToValidatedDesktopMS != 0 {
				report.TimingsMS.ToValidatedDesktopMS += baselineMS
			}
		}
		if current.ImageRoot != "" {
			trialErr = imageError(trialErr)
		}
		return report, trialErr
	}, func(r Report) error { return json.NewEncoder(out).Encode(r) })
}
