//go:build windows

package imagefactory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

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
	if err := inspectInstallation(ctx, dial, &r.Manifest); err != nil {
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
	// Repeat just before sanitation/publication: preparation facts alone cannot
	// certify that setup or validation left the installed definitions intact.
	if err := inspectInstallation(ctx, dial, &r.Manifest); err != nil {
		return err
	}
	b, err = guestRun(ctx, dial, sanitizeEntry, data)
	if err != nil || string(b) != "sanitized-shutdown-scheduled" {
		return errors.New("guest sanitation and shutdown acknowledgement failed")
	}
	return nil
}

func inspectInstallation(ctx context.Context, dial guestagent.Dialer, m *Manifest) error {
	var out boundedGuestOutput
	if guestagent.Run(ctx, dial, []string{guestagent.WindowsPath, "guest-agent", "selftest", "inspect"}, nil, &out) != nil {
		return errors.New("image installation selftest failed")
	}
	var f guestagent.InstallationFacts
	if json.Unmarshal(out.data, &f) != nil {
		return errors.New("image installation facts invalid")
	}
	if !f.Valid() {
		// Installation facts are fixed booleans and priorities, with no account
		// identifiers, so the whole set can explain which check refused.
		b, _ := json.Marshal(f)
		return fmt.Errorf("image installation facts invalid %s", b)
	}
	m.AgentTask = guestagent.TaskFacts{TaskUser: f.TaskUser, TaskHighest: f.TaskHighest, TaskInteractive: f.TaskInteractive, TaskAction: f.TaskAction, TaskPriority: f.TaskPriority}
	m.RunnerTask = f.RunnerTask
	m.AutologonAccountMatches = f.AutologonAccountMatches
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
			message := fmt.Sprintf("fixed guest operation exited at step %d", exit.Code)
			if script == validateEntry {
				if shape := probeFailureShape(out.data); shape != "" {
					message += " (" + shape + ")"
				}
			}
			return nil, errors.New(message)
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

// reportShape emits fixed labels and numbers only. In particular, never format
// UnmarshalTypeError.Value: overflowing numbers include the guest's literal.
// BOM: 0 absent, 1 UTF-8, 2 UTF-16LE, 3 UTF-16BE, 4 UTF-32LE, 5 UTF-32BE.
// Field: one-based Topology declaration order, 0 root/unknown.
// Kind: 0 unknown, 1 bool, 2 number, 3 string, 4 array, 5 object.
func reportShape(b []byte, err error) string {
	bom := 0
	for i, prefix := range [][]byte{{0xef, 0xbb, 0xbf}, {0xff, 0xfe}, {0xfe, 0xff}, {0xff, 0xfe, 0, 0}, {0, 0, 0xfe, 0xff}} {
		if bytes.HasPrefix(b, prefix) {
			bom = i + 1
		}
	}
	validUTF8, validJSON := 0, 0
	if utf8.Valid(b) {
		validUTF8 = 1
	}
	if json.Valid(b) {
		validJSON = 1
	}
	shape := fmt.Sprintf("len=%d bom=%d nul=%d utf8=%d json=%d", len(b), bom, bytes.Count(b, []byte{0}), validUTF8, validJSON)
	if len(b) > 0 {
		shape += fmt.Sprintf(" first=0x%02x last=0x%02x", b[0], b[len(b)-1])
	}
	var syntax *json.SyntaxError
	var kind *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		shape += fmt.Sprintf(" syntax_offset=%d", syntax.Offset)
	case errors.As(err, &kind):
		field, value := 0, 0
		topology := reflect.TypeFor[windesktop.Topology]()
		for i := range topology.NumField() {
			f := topology.Field(i)
			if kind.Field == f.Tag.Get("json") || kind.Field == f.Name {
				field = i + 1
			}
		}
		switch {
		case kind.Value == "bool":
			value = 1
		case strings.HasPrefix(kind.Value, "number"):
			value = 2
		case kind.Value == "string":
			value = 3
		case kind.Value == "array":
			value = 4
		case kind.Value == "object":
			value = 5
		}
		shape += fmt.Sprintf(" field=%d json_kind=%d offset=%d", field, value, kind.Offset)
	}
	return shape
}
