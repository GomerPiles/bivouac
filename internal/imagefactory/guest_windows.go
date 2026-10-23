//go:build windows

package imagefactory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/windesktop"
)

type boundedGuestOutput struct{ data []byte }

func (b *boundedGuestOutput) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 8192 {
		return 0, errors.New("guest output exceeds bound")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func waitAgent(ctx context.Context, dial guestagent.Dialer) error {
	for {
		attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := guestagent.Run(attempt, dial, []string{guestagent.WindowsPath, "version"}, nil, io.Discard)
		cancel()
		if err == nil {
			return nil
		}
		var version *guestagent.VersionError
		if errors.As(err, &version) {
			return errors.New("image agent protocol mismatch")
		}
		select {
		case <-ctx.Done():
			return errors.New("image agent unavailable")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Join the exit watcher before its creating handle can be closed or reused.
// Errors still take the factory's owned cleanup/offline-inspection path.
func prepareUntilExit(ctx context.Context, wait, prepare func(context.Context) error) error {
	work, cancelWork := context.WithCancelCause(ctx)
	defer cancelWork(nil)
	watch, cancelWatch := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := wait(watch)
		if watch.Err() == nil {
			if err != nil {
				cancelWork(errors.New("guest exit observation failed during preparation"))
			} else {
				cancelWork(errors.New("guest powered off before preparation completed"))
			}
		}
	}()
	defer func() { cancelWatch(); <-done }()
	err := prepare(work)
	cancelWatch()
	<-done
	return errors.Join(err, context.Cause(work))
}

func prepareGuest(ctx context.Context, c Config, r *record) error {
	dial := guestagent.DialHvsock(r.RuntimeID)
	return prepareGuestWithDial(ctx, c, r, dial)
}

func prepareGuestWithDial(ctx context.Context, c Config, r *record, dial guestagent.Dialer) error {
	if err := waitAgent(ctx, dial); err != nil {
		return err
	}
	data := map[string]any{"name": r.Name, "user": c.GuestUser, "sha256": r.Manifest.ProbeSHA256, "script_sha256": r.Manifest.ValidationSHA256, "autologon_sha256": r.Manifest.AutologonSHA256, "require_setup": true, "prepared": false}
	b, err := guestRun(ctx, dial, validateEntry, data)
	if err != nil {
		return errors.Join(errors.New("guest desktop validation failed"), err)
	}
	var topology windesktop.Topology
	if err := json.Unmarshal(b, &topology); err != nil {
		return fmt.Errorf("invalid topology report (%s)", reportShape(b, err))
	}
	r.Manifest.Topology = &topology
	if err := factoryDisplayReportOK(b); err != nil {
		return err
	}
	// VersionInfo reads no runner credentials and does not start the listener.
	b, err = guestRun(ctx, dial, `param($data);$helper='C:\ProgramData\Bivouac\Image\hcs-runner-check.ps1';if((Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash -ine $data.runner_check_sha256){exit 14};. $helper;if(!(Assert-CleanRunner 'C:\actions-runner')){exit 1};$v=(Get-Item -LiteralPath 'C:\actions-runner\bin\Runner.Listener.exe').VersionInfo.ProductVersion;if($v -match '^\d{1,4}\.\d{1,4}\.\d{1,4}$'){[Console]::Out.Write($v)}`, map[string]string{"runner_check_sha256": hashBytes([]byte(runnerCheck))})
	if err != nil {
		return errors.New("runner verification failed")
	}
	if len(b) > 32 {
		return errors.New("runner version exceeds bound")
	}
	if len(b) > 0 {
		for _, ch := range b {
			if ch != '.' && (ch < '0' || ch > '9') {
				return errors.New("invalid runner version")
			}
		}
		r.Manifest.RunnerVersion = string(b)
	}
	data = map[string]any{"name": r.Name, "user": c.GuestUser, "probe_sha256": r.Manifest.ProbeSHA256, "validation_sha256": r.Manifest.ValidationSHA256, "autologon_sha256": r.Manifest.AutologonSHA256, "sanitize_sha256": hashBytes([]byte(imageSanitize))}
	b, err = guestRun(ctx, dial, sanitizeEntry, data)
	if err != nil || string(b) != "sanitized-shutdown-scheduled" {
		return errors.New("guest sanitation and shutdown acknowledgement failed")
	}
	return nil
}

func guestRun(ctx context.Context, dial guestagent.Dialer, script string, data any) ([]byte, error) {
	b, err := guestInput(script, data)
	if err != nil {
		return nil, err
	}
	var out boundedGuestOutput
	err = guestagent.Run(ctx, dial, []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedPowerShell(guestBootstrap)}, bytes.NewReader(b), &out)
	if err != nil {
		var exit *guestagent.ExitError
		if errors.As(err, &exit) && exit.Code > 0 && exit.Code <= 255 {
			return nil, fmt.Errorf("fixed guest operation exited at step %d", exit.Code)
		}
		return nil, errors.New("fixed guest operation failed")
	}
	return out.data, nil
}

func factoryDisplayReportOK(b []byte) error {
	if !renderOK(b) {
		return errors.New("guest desktop rendering checks did not all pass")
	}
	var topology windesktop.Topology
	if err := json.Unmarshal(b, &topology); err != nil {
		return fmt.Errorf("invalid topology report (%s)", reportShape(b, err))
	}
	if !topology.SyntheticOK() {
		return errors.New("guest synthetic topology checks did not all pass")
	}
	return nil
}

func renderOK(b []byte) bool {
	var r struct {
		Ready            bool   `json:"guest_ready"`
		Desktop          bool   `json:"desktop_ready"`
		Hardware         bool   `json:"hardware_d3d11"`
		Presented        bool   `json:"presented"`
		Pixels           bool   `json:"pixel_readback"`
		Stage            uint32 `json:"stage"`
		HRESULT          uint32 `json:"hresult"`
		Vendor           uint32 `json:"vendor_id"`
		Device           uint32 `json:"device_id"`
		Adapters         uint32 `json:"adapter_count"`
		HardwareAdapters uint32 `json:"hardware_adapter_count"`
		GPUValid         bool   `json:"gpu_device_diagnostics_valid"`
		Displays         uint32 `json:"display_device_count"`
		Virtual          uint32 `json:"virtual_render_device_count"`
		Problem          uint32 `json:"virtual_render_problem_code"`
	}
	return json.Unmarshal(b, &r) == nil && r.Ready && r.Desktop && r.Hardware && r.Presented && r.Pixels && r.Stage == 7 && r.HRESULT == 0 && r.Vendor != 0 && (r.Vendor != 0x1414 || r.Device != 0x8c) && r.Adapters > 0 && r.Adapters <= 32 && r.HardwareAdapters > 0 && r.HardwareAdapters <= r.Adapters && r.GPUValid && r.Displays <= 32 && r.Virtual > 0 && r.Virtual <= r.Displays && r.Problem == 0
}

// reportShape describes a malformed guest report with numbers and this
// package's own field names only, never guest bytes.
func reportShape(b []byte, err error) string {
	shape := fmt.Sprintf("len=%d", len(b))
	if len(b) > 0 {
		shape += fmt.Sprintf(" first=0x%02x last=0x%02x", b[0], b[len(b)-1])
	}
	var syntax *json.SyntaxError
	var kind *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		shape += fmt.Sprintf(" syntax_offset=%d", syntax.Offset)
	case errors.As(err, &kind):
		shape += fmt.Sprintf(" field=%q json_kind=%q offset=%d", kind.Field, kind.Value, kind.Offset)
	}
	return shape
}
