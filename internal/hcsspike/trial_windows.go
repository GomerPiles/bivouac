//go:build windows

package hcsspike

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

var errMissing = errors.New("spike compute system absent")

type properties struct {
	ID         string `json:"Id"`
	Owner      string
	SystemType string
	RuntimeID  string `json:"RuntimeId"`
	State      string
}

type system interface {
	Properties(context.Context) (properties, error)
	Start(context.Context) error
	GPU(context.Context) error
	Terminate(context.Context) error
	Close()
}

type backend interface {
	Open(context.Context, string) (system, error)
	Prepare(context.Context, Config) error
	// settled is false when the dispatched create may still complete later.
	Create(context.Context, Config) (s system, settled bool, err error)
	Probe(context.Context, Config, string) (Report, error)
}

// Report is deliberately limited to observations, never guest-controlled text.
// Assignment/agent readiness alone do not prove rendering. The optional fixed
// interactive probe checks hardware D3D11, presentation and two-color GPU/desktop
// pixel readback; it does not test keyboard/mouse input.
type Report struct {
	NativeAbsent               bool   `json:"native_absent"`
	StorageRetained            bool   `json:"storage_retained"`
	GuestReady                 bool   `json:"guest_ready"`
	DesktopReady               bool   `json:"desktop_ready"`
	HardwareD3D11              bool   `json:"hardware_d3d11"`
	Presented                  bool   `json:"presented"`
	PixelReadback              bool   `json:"pixel_readback"`
	GuestValidationStep        uint32 `json:"guest_validation_step,omitempty"`
	RenderStage                uint32 `json:"render_stage,omitempty"`
	RenderHRESULT              uint32 `json:"render_hresult,omitempty"`
	RenderVendorID             uint32 `json:"render_vendor_id,omitempty"`
	RenderDeviceID             uint32 `json:"render_device_id,omitempty"`
	RenderAdapterCount         uint32 `json:"render_adapter_count,omitempty"`
	RenderHardwareAdapterCount uint32 `json:"render_hardware_adapter_count,omitempty"`
	RenderDefaultVendorID      uint32 `json:"render_default_vendor_id,omitempty"`
	RenderDefaultDeviceID      uint32 `json:"render_default_device_id,omitempty"`
	GPUDeviceDiagnosticsValid  bool   `json:"gpu_device_diagnostics_valid"`
	DisplayDeviceCount         uint32 `json:"display_device_count,omitempty"`
	VirtualRenderDeviceCount   uint32 `json:"virtual_render_device_count,omitempty"`
	VirtualRenderProblemCode   uint32 `json:"virtual_render_problem_code,omitempty"`
	GPUFilesCopied             uint32 `json:"gpu_files_copied,omitempty"`
	NativeStarted              bool   `json:"native_started"`
	AgentConnected             bool   `json:"agent_connected"`
	GPUAssigned                bool   `json:"gpu_assigned"`
	DisplayReady               bool   `json:"display_ready"`
	SSHAuthenticated           bool   `json:"ssh_authenticated"`
	SSHCommandReady            bool   `json:"ssh_command_ready"`
	SSHStdinReady              bool   `json:"ssh_stdin_ready"`
	Cleaned                    bool   `json:"cleaned"`
}

type record struct {
	Config        Config `json:"config"`
	Attempted     bool   `json:"attempted"`
	RuntimeID     string `json:"runtime_id,omitempty"`
	Deleting      bool   `json:"deleting,omitempty"`
	CreateSettled bool   `json:"create_settled,omitempty"`
}

type journal struct{ root *os.Root }

func openJournal(path string) (*journal, error) {
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &journal{root: r}, nil
}

func (j *journal) read(name string, out any) error {
	f, err := j.root.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 || json.Unmarshal(b, out) != nil {
		return errors.New("invalid bounded spike ownership record")
	}
	return nil
}

func (j *journal) write(name string, value any, exclusive bool) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	target := name
	if !exclusive {
		target += ".new"
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := j.root.OpenFile(target, flags, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err == nil && !exclusive {
		err = j.root.Rename(target, name)
	}
	if err != nil && !exclusive {
		_ = j.root.Remove(target)
	}
	return err
}

func recordName(c Config) string { return c.InstanceID + ".json" }
func markerName(c Config) string { return filepath.Join(c.InstanceID, "owner.json") }

func (j *journal) prove(c Config) error {
	var r record
	var marker Config
	if err := j.read(recordName(c), &r); err != nil {
		return err
	}
	if !reflect.DeepEqual(r.Config, c) {
		return errors.New("spike journal configuration differs")
	}
	if err := j.read(markerName(c), &marker); err != nil {
		return err
	}
	if !reflect.DeepEqual(marker, c) {
		return errors.New("spike child ownership differs")
	}
	return nil
}

func proveNative(c Config, r record, p properties) error {
	if !strings.HasPrefix(p.ID, "bivouac-") || p.ID != c.name() || p.Owner != c.owner() || p.SystemType != "VirtualMachine" || (r.RuntimeID != "" && !strings.EqualFold(r.RuntimeID, p.RuntimeID)) {
		return errors.New("native spike ownership differs; instance retained")
	}
	return nil
}

func absent(ctx context.Context, api backend, name string) error {
	s, err := api.Open(ctx, name)
	if errors.Is(err, errMissing) {
		return nil
	}
	if err != nil {
		return err
	}
	s.Close()
	return errors.New("native name already exists; refusing to replace it")
}

func trial(ctx context.Context, c Config, j *journal, api backend, bootOnly, retainFailed bool) (report Report, result error) {
	if err := c.Validate(); err != nil {
		return report, err
	}
	if err := absent(ctx, api, c.name()); err != nil {
		return report, err
	}
	// Do not reuse a root containing interrupted work or another trial.
	entries, err := fs.ReadDir(j.root.FS(), ".")
	if err != nil {
		return report, err
	}
	for _, entry := range entries {
		if entry.Name() != "daemon.lock" {
			return report, errors.New("spike root contains retained work; use matching cleanup first")
		}
	}
	r := record{Config: c}
	if err = j.write(recordName(c), r, true); err != nil {
		return report, err
	}
	var created system
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		defer cancel()
		err := cleanupHeld(cleanupCtx, c, j, api, created, retainFailed && result != nil)
		_, childErr := j.root.Stat(c.InstanceID)
		_, recordErr := j.root.Stat(recordName(c))
		report.StorageRetained = childErr == nil || recordErr == nil
		report.NativeAbsent = err == nil
		report.Cleaned = err == nil && !report.StorageRetained
		result = errors.Join(result, err)
	}()
	if err = j.root.Mkdir(c.InstanceID, 0o700); err != nil {
		return report, err
	}
	if err = j.write(markerName(c), c, true); err != nil {
		return report, err
	}
	if err = api.Prepare(ctx, c); err != nil {
		return report, err
	}
	r.Attempted = true
	if err = j.write(recordName(c), r, false); err != nil {
		return report, err
	}
	s, settled, err := api.Create(ctx, c)
	if s != nil {
		if err == nil {
			created = s
		} else {
			s.Close()
		}
	}
	if settled {
		r.CreateSettled = true
		if writeErr := j.write(recordName(c), r, false); writeErr != nil {
			return report, errors.Join(err, writeErr)
		}
	}
	if err != nil {
		return report, err
	} // never blindly replay a mutation
	p, err := s.Properties(ctx)
	if err != nil {
		return report, err
	}
	if err = proveNative(c, r, p); err != nil {
		return report, err
	}
	if err = s.Start(ctx); err != nil {
		return report, err
	}
	p, err = s.Properties(ctx)
	if err != nil {
		return report, err
	}
	if err = proveNative(c, r, p); err != nil {
		return report, err
	}
	if p.RuntimeID == "" || p.State != "Running" {
		return report, errors.New("spike VM did not report a running runtime identity")
	}
	report.NativeStarted = true
	r.RuntimeID = p.RuntimeID
	if err = j.write(recordName(c), r, false); err != nil {
		return report, err
	}
	if c.GPU {
		if err = s.GPU(ctx); err != nil {
			return report, err
		}
		report.GPUAssigned = true
	}
	if bootOnly {
		return report, nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	observed, err := api.Probe(probeCtx, c, p.RuntimeID)
	observed.NativeStarted = report.NativeStarted
	observed.GPUAssigned = report.GPUAssigned
	return observed, err
}

func cleanup(ctx context.Context, c Config, j *journal, api backend) error {
	return cleanupHeld(ctx, c, j, api, nil, false)
}

// Keep the trial's last live handle until ownership is verified and termination
// completes. Closing it first starts an asynchronous automatic teardown, during
// which property queries can fail with HCS_E_INVALID_STATE.
func cleanupHeld(ctx context.Context, c Config, j *journal, api backend, held system, retain bool) error {
	if held != nil {
		defer held.Close()
	}

	if err := c.Validate(); err != nil {
		return err
	}
	var r record
	if err := j.read(recordName(c), &r); err != nil {
		return err
	}
	if !reflect.DeepEqual(r.Config, c) {
		return errors.New("spike journal configuration differs")
	}
	proofErr := j.prove(c)
	if proofErr != nil {
		// An interrupted intent may have no child, or only an empty child.
		// Interrupted deletion may already have removed its marked child.
		// Neither case permits stopping a native VM or recursive deletion.
		if !errors.Is(proofErr, os.ErrNotExist) || (r.Attempted && !r.Deleting) {
			return proofErr
		}
		if err := absent(ctx, api, c.name()); err != nil {
			return err
		}
		if !r.Attempted {
			if err := j.root.Remove(c.InstanceID); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else if err := j.root.Remove(c.InstanceID); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("nonempty unmarked spike child retained")
		}
		return removeJournal(c, j)
	}
	s := held
	var err error
	if s == nil {
		s, err = api.Open(ctx, c.name())
	}
	if err == nil {
		defer s.Close()
		if !r.Attempted {
			return errors.New("native guest exists without recorded create dispatch; retained")
		}
		p, queryErr := s.Properties(ctx)
		if queryErr != nil {
			return queryErr
		}
		if err = proveNative(c, r, p); err != nil {
			return err
		}
		// Seeing our exact native instance resolves a lost create response;
		// the same dispatch cannot later create a second instance of that ID.
		r.CreateSettled = true
		if err = j.write(recordName(c), r, false); err != nil {
			return err
		}
		if err = s.Terminate(ctx); err != nil {
			return err
		}
		s.Close()
	} else if !errors.Is(err, errMissing) {
		return err
	}
	if r.Attempted && !r.CreateSettled {
		return errors.New("create outcome remains unknown; native absence alone cannot release spike storage")
	}
	// Terminate completion is not proof of native absence. Poll only this name.
	for {
		if err = absent(ctx, api, c.name()); err == nil {
			break
		}
		if ctx.Err() != nil {
			return errors.New("native absence unconfirmed; spike storage retained")
		}
		select {
		case <-ctx.Done():
			return errors.New("native absence unconfirmed; spike storage retained")
		case <-time.After(200 * time.Millisecond):
		}
	}
	// The relative target is derived from a validated ID and stays under the
	// open root. Recheck both durable proofs before removing only this child.
	if err = j.prove(c); err != nil {
		return err
	}
	// Diagnostic retention still terminates and confirms absence; it never
	// keeps a live guest or permits inspection of an ambiguous create.
	if retain {
		return nil
	}
	r.Deleting = true
	if err = j.write(recordName(c), r, false); err != nil {
		return err
	}
	// Keep the marker until all payloads have been removed. If interrupted
	// after marker removal, recovery can remove only an empty child.
	for _, path := range []string{"drivers", "setup-assets", "setup-private", "disk.vhdx", "vm.vmgs", "vm.vmrs"} {
		if err = j.root.RemoveAll(filepath.Join(c.InstanceID, path)); err != nil {
			return err
		}
	}
	if err = j.root.Remove(markerName(c)); err != nil {
		return err
	}
	if err = j.root.Remove(c.InstanceID); err != nil {
		return err
	}
	return removeJournal(c, j)
}

func removeJournal(c Config, j *journal) error {
	if err := j.root.Remove(recordName(c) + ".new"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return j.root.Remove(recordName(c))
}
