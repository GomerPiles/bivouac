//go:build windows

package imagefactory

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/hcs"
	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/vmhost"
	"github.com/GomerPiles/bivouac/internal/winhost"
	"github.com/Microsoft/go-winio/vhd"
	"golang.org/x/sys/windows"
)

func RequireElevated() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("image build, inspect and cleanup require one elevated foreground process; launch from an administrator shell")
	}
	return nil
}

func LoadConfig(path string) (Config, error) {
	return loadConfig(path, winhost.CheckProtected)
}

func loadConfig(path string, check func(string) error) (Config, error) {
	if !localPath(path) {
		return Config{}, errors.New("--config must name a local absolute protected JSON file")
	}
	if check(path) != nil {
		return Config{}, errors.New("image configuration must be administrator-protected")
	}
	f, err := openReadOnlyPinned(path)
	if err != nil {
		return Config{}, err
	}
	defer func() { _ = f.Close() }()
	return DecodeConfig(f)
}

// Build is deliberately synchronous. Its creating handle remains owned until
// shutdown or failure cleanup has settled; no service or journal is contacted.
func Build(ctx context.Context, c Config, log *slog.Logger) (_ Manifest, err error) {
	return runFactory(ctx, c, log, nil)
}

// Inspect shares the exact copy/child/inspection path with Build, prints the
// recorded facts before deferred cleanup, and never enters preparation or boot.
func Inspect(ctx context.Context, c Config, log *slog.Logger, out io.Writer) error {
	if out == nil {
		return errors.New("image inspect requires an output writer")
	}
	_, err := runFactory(ctx, c, log, out)
	return err
}

func runFactory(ctx context.Context, c Config, log *slog.Logger, inspectOut io.Writer) (result Manifest, err error) {
	if err = RequireElevated(); err != nil {
		return Manifest{}, err
	}
	if err = c.Validate(); err != nil {
		return Manifest{}, err
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if err = winhost.CheckProtected(c.ImageRoot); err != nil {
		return Manifest{}, errors.New("image root must already be administrator-protected")
	}
	if err = winhost.CheckProtected(c.Source); err != nil {
		return Manifest{}, errors.New("source must be administrator-protected")
	}
	if err = checkFinalInputs(c); err != nil {
		return Manifest{}, err
	}
	api, err := hcs.Load()
	if err != nil {
		return Manifest{}, err
	}
	buildRoot := filepath.Join(c.ImageRoot, ".builds")
	if _, statErr := os.Lstat(buildRoot); errors.Is(statErr, os.ErrNotExist) {
		if err = newProtectedDirectory(buildRoot); err != nil {
			return Manifest{}, err
		}
	}
	if err = winhost.CheckProtected(buildRoot); err != nil {
		return Manifest{}, err
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return Manifest{}, err
	}
	id := hex.EncodeToString(random[:])
	name, _ := GuestName(id)
	workspace := filepath.Join(buildRoot, id)
	if err = newProtectedDirectory(workspace); err != nil {
		return Manifest{}, err
	}
	lock, err := lockWorkspace(workspace)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { _ = lock.Close() }()
	r := &record{BuildID: id, Workspace: workspace, Name: name, Owner: ownerID(c.ImageRoot, id), Phase: "created", Manifest: Manifest{BuildID: id, GuestName: name, GuestUser: c.GuestUser, Source: c.Source, SourceSHA256: strings.ToLower(c.SourceSHA256), Output: filepath.Join(c.ImageRoot, id, "disk.vhdx"), ProbeSHA256: strings.ToLower(c.RenderProbe.SHA256), ValidationSHA256: hashBytes([]byte(guestValidate)), AutologonSHA256: hashBytes([]byte(autologonSecret)), Assets: map[string]string{}, Revision: revision(), Started: time.Now().UTC(), PhaseMS: map[string]int64{}}}
	if err = writeJSON(filepath.Join(workspace, "owner.json"), r); err != nil {
		// No native or disk operation has occurred, and this invocation created
		// both entries. Remove only these entries, without recursive traversal.
		removeMarker := os.Remove(filepath.Join(workspace, "owner.json"))
		if errors.Is(removeMarker, os.ErrNotExist) {
			removeMarker = nil
		}
		return Manifest{}, errors.Join(errors.New("workspace ownership recording failed"), err, removeMarker, os.Remove(filepath.Join(workspace, "build.lock")), os.Remove(workspace))
	}
	var system *hcs.System
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		var terminate func() error
		if system != nil {
			terminate = func() error { defer system.Close(); return system.Terminate(cleanupCtx) }
		}
		cleanupErr := cleanupOwned(terminate, func() error { return waitAbsent(cleanupCtx, api, r.Name) }, func() error {
			if r.NativeAttempted && !r.GuestCompleted && err != nil {
				facts, diagnosticErr := inspectOwned(cleanupCtx, c, r, true, runHost)
				r.hostError("setup_diagnostics", diagnosticErr)
				if facts != nil {
					err = errors.Join(err, r.setupFailure(facts))
				}
				if diagnosticErr != nil {
					err = errors.Join(err, fmt.Errorf("offline setup diagnostics unavailable: %w", diagnosticErr))
				}
			}
			return detachOwned(cleanupCtx, r)
		}, func() error { return removeOwned(r) })
		r.Retained = cleanupErr != nil
		if err != nil {
			r.Phase = "failed"
		} else if cleanupErr == nil {
			r.Phase = "complete"
		}
		r.Manifest.Ended = time.Now().UTC()
		err = errors.Join(err, cleanupErr, r.save())
		if r.Retained {
			log.Error("image build workspace retained", "build_id", id)
		}
		if r.Published && err != nil {
			result = r.Manifest
			err = &PublishedError{BuildID: id, Err: err}
		}
	}()
	if err = r.save(); err != nil {
		return Manifest{}, err
	}
	buildCtx := ctx
	phase := func(label string, run func() error) error {
		r.Phase = label
		if e := r.save(); e != nil {
			return e
		}
		log.Info("image build phase", "build_id", id, "phase", label)
		begun := time.Now()
		e := run()
		r.hostError(label, e)
		r.Manifest.PhaseMS[label] = time.Since(begun).Milliseconds()
		return errors.Join(e, r.save())
	}
	if err = phase("source_copy", func() error {
		var e error
		r.Manifest.Template, e = ownerTemplate(c)
		if e != nil {
			return e
		}
		size, e := diskSize(c.Source)
		if e != nil {
			return e
		}
		space, e := admitSpace(c.ImageRoot, "source_copy", size, 0, false)
		r.SpaceChecks = append(r.SpaceChecks, space)
		if e != nil {
			return e
		}
		_, _, e = copyPinned(buildCtx, c.Source, filepath.Join(workspace, "source.vhdx"), c.SourceSHA256, 256<<30)
		if e != nil {
			return e
		}
		return verifyStandalone(filepath.Join(workspace, "source.vhdx"))
	}); err != nil {
		return Manifest{}, err
	}
	if err = vhd.CreateDiffVhd(r.disk(), filepath.Join(workspace, "source.vhdx"), 0); err != nil {
		return Manifest{}, errors.New("cannot create owned differencing disk")
	}
	err = phase("inspection", func() error {
		facts, e := inspectOwned(buildCtx, c, r, false, runHost)
		r.Inspection = facts
		if e != nil {
			return e
		}
		if !facts.Eligible() {
			return errors.New("offline inspection refused image; specific facts saved in build record")
		}
		return nil
	})
	if inspectOut != nil {
		printErr := json.NewEncoder(inspectOut).Encode(InspectionReport{BuildID: id, Facts: r.Inspection})
		return r.Manifest, errors.Join(err, printErr)
	}
	if err != nil {
		return Manifest{}, err
	}
	if err = phase("preparation", func() error {
		if e := r.Inspection.RunnerInput(c); e != nil {
			return e
		}
		var e error
		r.Manifest.Drivers, e = copyDrivers(buildCtx, c, r)
		if e != nil {
			return e
		}
		if e := prepareMedia(buildCtx, c, r); e != nil {
			return e
		}
		if e = api.CreateGuestStateFiles(filepath.Join(workspace, "vm.vmgs"), filepath.Join(workspace, "vm.vmrs")); e != nil {
			return e
		}
		// Keep ownership records and the workspace directory private. Only the
		// VM's payloads need grants; all are checked before any ACL changes.
		paths := []string{r.disk(), filepath.Join(workspace, "source.vhdx"), filepath.Join(workspace, "vm.vmgs"), filepath.Join(workspace, "vm.vmrs"), filepath.Join(workspace, "setup-private"), filepath.Join(workspace, "setup-private", "setup.iso")}
		for _, path := range paths {
			if e = winhost.CheckProtected(path); e != nil {
				return e
			}
		}
		for _, path := range paths {
			if e = grantOwned(api, r, path); e != nil {
				return e
			}
		}
		return nil
	}); err != nil {
		return Manifest{}, err
	}
	if err = requireHeadroom(c); err != nil {
		return Manifest{}, err
	}
	guestCtx, cancelGuest := context.WithTimeout(buildCtx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancelGuest()
	guardCtx, stopGuard := context.WithCancelCause(guestCtx)
	guardDone := make(chan struct{})
	go func() { defer close(guardDone); watchResources(guardCtx, c, stopGuard) }()
	defer func() { stopGuard(nil); <-guardDone }()
	if err = phase("boot_and_validate", func() error {
		var e error
		r.NativeAttempted = true
		if e = r.save(); e != nil {
			return e
		}
		system, e = api.Create(guardCtx, r.Name, document(c, r))
		if e != nil {
			return e
		}
		p, e := system.Properties(guardCtx)
		if e != nil {
			return e
		}
		if e = prove(r, p, false); e != nil {
			return e
		}
		r.RuntimeID = p.RuntimeID
		if e = r.save(); e != nil {
			return e
		}
		if e = system.Start(guardCtx); e != nil {
			return e
		}
		if e = system.Modify(guardCtx, hcs.AssignDefaultGPU()); e != nil {
			return e
		}
		p, e = system.Properties(guardCtx)
		if e != nil {
			return e
		}
		if e = prove(r, p, true); e != nil {
			return e
		}
		r.RuntimeID = p.RuntimeID
		if e = r.save(); e != nil {
			return e
		}
		return prepareUntilExit(guardCtx, func(ctx context.Context) error {
			_, err := system.WaitExit(ctx)
			return err
		}, func(ctx context.Context) error { return prepareGuest(ctx, c, r) })
	}); err != nil {
		return Manifest{}, errors.Join(err, context.Cause(guardCtx))
	}
	if err = phase("clean_shutdown", func() error {
		exit, e := system.WaitExit(guardCtx)
		if e != nil {
			return e
		}
		if !exit.Graceful() {
			return errors.New("image requires native GracefulExit")
		}
		system.Close()
		system = nil
		return waitAbsent(guardCtx, api, r.Name)
	}); err != nil {
		return Manifest{}, err
	}
	stopGuard(nil)
	<-guardDone
	if cause := context.Cause(guardCtx); cause != nil && !errors.Is(cause, context.Canceled) {
		return Manifest{}, cause
	}
	r.GuestCompleted = true
	if err = phase("publication", func() error {
		if e := buildCtx.Err(); e != nil {
			return e
		}
		sourceSize, e := diskSize(filepath.Join(workspace, "source.vhdx"))
		if e != nil {
			return e
		}
		childSize, e := diskSize(r.disk())
		if e != nil {
			return e
		}
		space, e := admitSpace(c.ImageRoot, "publication", sourceSize, childSize, true)
		r.SpaceChecks = append(r.SpaceChecks, space)
		if e != nil {
			return e
		}
		dir := filepath.Dir(r.Manifest.Output)
		if e := newProtectedDirectory(dir); e != nil {
			return e
		}
		if e := writeJSON(filepath.Join(dir, "owner.json"), map[string]string{"build_id": id}); e != nil {
			return e
		}
		if e := vmhost.Flatten(r.disk(), r.Manifest.Output); e != nil {
			return e
		}
		if e := verifyStandalone(r.Manifest.Output); e != nil {
			return e
		}
		if e := protect(dir, r.Manifest.Output, true); e != nil {
			return e
		}
		if e := winhost.CheckProtected(r.Manifest.Output); e != nil {
			return e
		}
		r.Manifest.Size, r.Manifest.SHA256, e = hashFile(buildCtx, r.Manifest.Output)
		return e
	}); err != nil {
		return Manifest{}, err
	}
	r.Manifest.Ended = time.Now().UTC()
	// Manifest publication is the commit point. Everything before it is private
	// incomplete output, and no pre-existing output directory is ever reused.
	if err = publishManifest(filepath.Join(filepath.Dir(r.Manifest.Output), "manifest.json"), r.Manifest); err != nil {
		return Manifest{}, err
	}
	r.Published = true
	return r.Manifest, nil
}

func ownerID(root, id string) string {
	return "bivouac-image:" + hashBytes([]byte(strings.ToLower(root)))[:16] + ":" + id
}
func revision() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return "unknown"
}
func prove(r *record, p hcs.Properties, running bool) error {
	if !strings.HasPrefix(r.Name, "bivouac-") || p.ID != r.Name || p.Owner != r.Owner || p.SystemType != hcs.SystemTypeVM || (r.RuntimeID != "" && p.RuntimeID != r.RuntimeID) || (running && (p.RuntimeID == "" || p.State != hcs.StateRunning)) {
		return errors.New("image build native ownership mismatch")
	}
	return nil
}

func detachOwned(ctx context.Context, r *record) error {
	if _, err := os.Lstat(r.disk()); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	_, err := runHost(ctx, detachDisk, r.scriptData(), false)
	r.hostError("detach", err)
	return err
}
func removeOwned(r *record) error {
	if err := checkWorkspace(r); err != nil {
		return err
	}
	if !r.Published {
		dir := filepath.Dir(r.Manifest.Output)
		if _, err := os.Lstat(dir); err == nil {
			if err = winhost.CheckProtected(dir); err != nil {
				return err
			}
			var marker struct {
				BuildID string `json:"build_id"`
			}
			b, err := os.ReadFile(filepath.Join(dir, "owner.json"))
			if err != nil || json.Unmarshal(b, &marker) != nil || marker.BuildID != r.BuildID {
				return errors.New("incomplete output ownership unproven; retained")
			}
			// Publication may have completed just before the creating process
			// lost power, without its record being updated. Never remove it.
			if _, err = os.Lstat(filepath.Join(dir, "manifest.json")); err == nil {
				f, e := os.Open(filepath.Join(dir, "manifest.json"))
				if e != nil {
					return e
				}
				var m Manifest
				e = json.NewDecoder(io.LimitReader(f, 65536)).Decode(&m)
				_ = f.Close()
				if e != nil || m.BuildID != r.BuildID || m.Output != r.Manifest.Output || m.SHA256 != r.Manifest.SHA256 || m.GuestName != r.Name {
					return errors.New("publication manifest does not match build; retained")
				}
				r.Published = true
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if !r.Published {
				if err = os.RemoveAll(dir); err != nil {
					return err
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.RemoveAll(r.Workspace)
}
func checkWorkspace(r *record) error {
	if !validID(r.BuildID) || filepath.Base(r.Workspace) != r.BuildID || filepath.Base(filepath.Dir(r.Workspace)) != ".builds" {
		return errors.New("invalid build workspace identity")
	}
	if err := winhost.CheckProtected(r.Workspace); err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(r.Workspace, "owner.json"))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var marker record
	if json.NewDecoder(io.LimitReader(f, 65536)).Decode(&marker) != nil || marker.BuildID != r.BuildID || marker.Workspace != r.Workspace || marker.Owner != r.Owner || marker.Name != r.Name {
		return errors.New("workspace ownership marker differs")
	}
	return nil
}

// Cleanup does not adopt or terminate an arbitrary reopened system. The
// creating process's last-handle policy settles it; cleanup waits for absence.
func Cleanup(ctx context.Context, c Config, id string) error {
	if err := RequireElevated(); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if !validID(id) {
		return errors.New("invalid image build ID")
	}
	workspace := filepath.Join(c.ImageRoot, ".builds", id)
	path := workspace + ".json"
	if err := winhost.CheckProtected(path); err != nil {
		return err
	}
	f, err := openReadOnlyPinned(path)
	if err != nil {
		return err
	}
	var r record
	decodeErr := json.NewDecoder(io.LimitReader(f, 65536)).Decode(&r)
	_ = f.Close()
	if decodeErr != nil || r.BuildID != id || r.Workspace != workspace || r.Owner != ownerID(c.ImageRoot, id) || r.Manifest.Output != filepath.Join(c.ImageRoot, id, "disk.vhdx") {
		return errors.New("retained build record does not match configuration")
	}
	name, _ := GuestName(id)
	if r.Name != name {
		return errors.New("retained build name differs")
	}
	if err = checkWorkspace(&r); err != nil {
		return err
	}
	lock, err := lockWorkspace(workspace)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	api, err := hcs.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	err = cleanupOwned(nil, func() error { return waitAbsent(ctx, api, name) }, func() error { return detachOwned(ctx, &r) }, func() error { return removeOwned(&r) })
	r.Retained = err != nil
	if err == nil {
		r.Phase = "cleaned"
	}
	return errors.Join(err, r.save())
}

func hashFile(ctx context.Context, path string) (int64, string, error) {
	f, err := openReadOnlyPinned(path)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = f.Close() }()
	// Reuse the bounded copy loop for hashing without staging another file.
	h := sha256.New()
	n, err := copyContext(ctx, h, f, 256<<30)
	return n, hex.EncodeToString(h.Sum(nil)), err
}

func requireHeadroom(c Config) error {
	s, err := perf.NewSampler(c.ImageRoot).Sample()
	if err != nil {
		return errors.New("host memory counters unavailable")
	}
	return admission(c.MemoryMB, s)
}
func admission(memoryMB uint64, s perf.Sample) error {
	if !validMemory(s) || s.AvailableBytes < (memoryMB<<20)+(10<<30) || s.Commit.HeadroomBytes() < (memoryMB<<20)+(8<<30) {
		return errors.New("build needs guest memory plus 10 GiB available and plus 8 GiB commit headroom")
	}
	return nil
}
func validMemory(s perf.Sample) bool {
	return s.TotalBytes > 0 && s.AvailableBytes <= s.TotalBytes && s.Commit != nil && s.Commit.LimitBytes > 0 && s.Commit.UsedBytes <= s.Commit.LimitBytes
}
func reserveLost(s perf.Sample) bool {
	return !validMemory(s) || s.AvailableBytes < 6<<30 || s.Commit.HeadroomBytes() < 2<<30
}
func watchResources(ctx context.Context, c Config, cancel context.CancelCauseFunc) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s, err := perf.NewSampler(c.ImageRoot).Sample()
			if err != nil || reserveLost(s) {
				cancel(errors.New("host memory reserve lost; canceling image build"))
				return
			}
		}
	}
}

func document(c Config, r *record) hcs.ComputeSystem {
	services := map[string]hcs.HvSocketService{guestagent.ServiceID: {BindSecurityDescriptor: "D:P(A;;FA;;;SY)(A;;FA;;;BA)", ConnectSecurityDescriptor: "D:P(A;;FA;;;SY)(A;;FA;;;BA)"}}
	return hcs.ComputeSystem{Owner: r.Owner, SchemaVersion: hcs.Schema21(), TerminateOnLastHandleClosed: true, VirtualMachine: &hcs.VirtualMachine{
		Chipset:          hcs.Chipset{Uefi: &hcs.Uefi{Console: "Default", ApplySecureBootTemplate: "Apply", SecureBootTemplateID: hcs.SecureBootMicrosoftWindows}},
		ComputeTopology:  hcs.Topology{Memory: hcs.Memory{SizeInMB: c.MemoryMB}, Processor: hcs.Processor{Count: c.CPU}},
		Devices:          hcs.Devices{Scsi: map[string]hcs.Scsi{"Primary": {Attachments: map[string]hcs.Attachment{"0": {Type: hcs.AttachmentVirtualDisk, Path: r.disk()}, "1": {Type: hcs.AttachmentISO, Path: filepath.Join(r.Workspace, "setup-private", "setup.iso"), ReadOnly: true}}}}, VideoMonitor: &hcs.VideoMonitor{HorizontalResolution: 1024, VerticalResolution: 768}, Keyboard: &hcs.Keyboard{}, Mouse: &hcs.Mouse{}, HvSocket: &hcs.HvSocket{HvSocketConfig: hcs.HvSocketConfig{ServiceTable: services}}},
		SecuritySettings: &hcs.SecuritySettings{EnableTpm: true, Isolation: &hcs.Isolation{IsolationType: hcs.IsolationGuestStateOnly}}, GuestState: &hcs.GuestState{GuestStateFilePath: filepath.Join(r.Workspace, "vm.vmgs"), RuntimeStateFilePath: filepath.Join(r.Workspace, "vm.vmrs")},
	}}
}
