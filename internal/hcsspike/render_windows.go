//go:build windows

package hcsspike

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"
)

//go:embed guest_validate.ps1
var guestValidate string

// Keep the remote command below cmd.exe's limit, independently of script/probe
// growth. A fixed entry script and metadata are sent as small JSON on stdin.
const guestValidateBootstrap = `$ErrorActionPreference='Stop';function Write-SpikeStep([int]$s){[Console]::Error.WriteLine('BIVOUAC_HCS_STEP:'+$s);if($p.data.require_setup -eq $true){try{[IO.File]::WriteAllText(($env:SystemRoot+'\AppSandbox\hcs-spike-validation-step.json'),('{"step":'+$s+'}'))}catch{}}};function Read-SpikeBytes([int]$n){$b=New-Object byte[] $n;$o=0;while($o -lt $n){$r=$i.Read($b,$o,[Math]::Min(4096,$n-$o));if($r -le 0){throw 'frame'};$o+=$r};return ,$b};try{Write-SpikeStep 1;$i=[Console]::OpenStandardInput();$n=[BitConverter]::ToUInt32((Read-SpikeBytes 4),0);if(!$n -or $n -gt 100000000){exit 18};Write-SpikeStep 4;$b=Read-SpikeBytes $n;Write-SpikeStep 2;$p=[Text.Encoding]::UTF8.GetString($b)|ConvertFrom-Json;Write-SpikeStep 3;& ([ScriptBlock]::Create($p.script)) $p.data}catch{exit 18}`

// Public validation assets arrive on setup media (or are preinstalled in a
// specialized image). SSH carries only a fixed entry command and metadata.
const guestValidateEntry = `param($data);$f=Join-Path $env:SystemRoot 'AppSandbox\hcs-spike-validate.ps1';if((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ine $data.script_sha256){exit 14};& $f $data`

func desktopScriptInput(c Config) ([]byte, error) {
	return guestScriptInput(guestValidateEntry, map[string]any{"name": c.name(), "user": c.GuestUser, "sha256": c.RenderProbe.SHA256, "script_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(guestValidate))), "require_setup": len(c.SetupAssets) != 0})
}

func desktopValidationCommand() string {
	return "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encodedPowerShell(guestValidateBootstrap)
}

type renderResult struct {
	ValidationStep            uint32 `json:"-"`
	GuestReady                bool   `json:"guest_ready"`
	DesktopReady              bool   `json:"desktop_ready"`
	HardwareD3D11             bool   `json:"hardware_d3d11"`
	Presented                 bool   `json:"presented"`
	PixelReadback             bool   `json:"pixel_readback"`
	Stage                     uint32 `json:"stage"`
	HRESULT                   uint32 `json:"hresult"`
	VendorID                  uint32 `json:"vendor_id"`
	DeviceID                  uint32 `json:"device_id"`
	AdapterCount              uint32 `json:"adapter_count"`
	HardwareAdapterCount      uint32 `json:"hardware_adapter_count"`
	DefaultVendorID           uint32 `json:"default_vendor_id"`
	DefaultDeviceID           uint32 `json:"default_device_id"`
	GPUDeviceDiagnosticsValid bool   `json:"gpu_device_diagnostics_valid"`
	DisplayDeviceCount        uint32 `json:"display_device_count"`
	VirtualRenderDeviceCount  uint32 `json:"virtual_render_device_count"`
	VirtualRenderProblemCode  uint32 `json:"virtual_render_problem_code"`
}
type boundedOutput struct{ data []byte }

func (w *boundedOutput) Write(b []byte) (int, error) {
	if len(w.data)+len(b) > 4096 {
		return 0, errors.New("guest validation output exceeds bound")
	}
	w.data = append(w.data, b...)
	return len(b), nil
}
func validateRenderReport(b []byte) (renderResult, error) {
	var r renderResult
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	decodeErr := d.Decode(&r)
	if decodeErr == nil {
		decodeErr = d.Decode(new(any))
		if errors.Is(decodeErr, io.EOF) {
			decodeErr = nil
		} else if decodeErr == nil {
			decodeErr = errors.New("multiple reports")
		}
	}
	if decodeErr != nil {
		offset := d.InputOffset()
		var syntax *json.SyntaxError
		var wrongType *json.UnmarshalTypeError
		if errors.As(decodeErr, &syntax) {
			offset = syntax.Offset
		} else if errors.As(decodeErr, &wrongType) {
			offset = wrongType.Offset
		}
		// Guest-controlled text and decoder error details never reach the sink.
		return r, fmt.Errorf("invalid bounded guest rendering report (bytes=%d, offset=%d)", len(b), offset)
	}
	if r.DisplayDeviceCount > 32 || r.VirtualRenderDeviceCount > r.DisplayDeviceCount || r.VirtualRenderProblemCode > 255 {
		return r, errors.New("invalid bounded guest GPU device counters")
	}
	if r.AdapterCount == 0 || r.AdapterCount > 32 || r.HardwareAdapterCount == 0 || r.HardwareAdapterCount > r.AdapterCount || !r.GuestReady || !r.DesktopReady || !r.HardwareD3D11 || !r.Presented || !r.PixelReadback || r.Stage != 7 || r.HRESULT != 0 || r.VendorID == 0 || (r.VendorID == 0x1414 && r.DeviceID == 0x8c) {
		return r, errors.New("guest rendering checks did not all pass")
	}
	return r, nil
}

// A timed-out SSH request closes the owned client, including requests that
// have not yet acknowledged session/command creation. No command is replayed.
func runGuestSSH(ctx context.Context, client *ssh.Client, command string, input []byte) ([]byte, uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	session, err := client.NewSession()
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = session.Close() }()
	var out boundedOutput
	session.Stdin = bytes.NewReader(input)
	session.Stdout = &out
	var progress validationProgress
	session.Stderr = &progress
	err = session.Run(command)
	return out.data, progress.step, err
}

func guestScriptInput(script string, data any) ([]byte, error) {
	input, err := json.Marshal(map[string]any{"script": script, "data": data})
	if err != nil {
		return nil, err
	}
	if len(input) > 100000000 {
		return nil, errors.New("guest script input exceeds bound")
	}
	framed := make([]byte, 4, len(input)+4)
	binary.LittleEndian.PutUint32(framed, uint32(len(input))) // #nosec G115 -- The immutable input length is checked above against a 100 MB cap.
	return append(framed, input...), nil
}

func checkSSHExecution(ctx context.Context, client *ssh.Client, report *Report) error {
	commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	command := "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encodedPowerShell(`[Console]::Out.Write('ready')`)
	out, _, err := runGuestSSH(commandCtx, client, command, nil)
	cancel()
	if err != nil || string(out) != "ready" {
		return errors.New("fixed SSH command execution check failed")
	}
	report.SSHCommandReady = true
	input, err := guestScriptInput(`param($data);[Console]::Out.Write($data.value)`, map[string]string{"value": "ready"})
	if err != nil {
		return errors.New("cannot encode fixed SSH stdin check")
	}
	stdinCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	out, _, err = runGuestSSH(stdinCtx, client, desktopValidationCommand(), input)
	cancel()
	if err != nil || string(out) != "ready" {
		return errors.New("fixed SSH framed-stdin check failed")
	}
	report.SSHStdinReady = true
	return nil
}

func validateDesktop(ctx context.Context, client *ssh.Client, c Config) (renderResult, error) {
	var r renderResult
	_, err := readPinned(*c.RenderProbe)
	if err != nil {
		return r, err
	}
	data, err := desktopScriptInput(c)
	if err != nil {
		return r, err
	}
	// Readiness has a three-minute bound and the interactive probe at most fifty
	// seconds; leave transfer/startup headroom while keeping the trial deadline.
	validationCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	out, step, err := runGuestSSH(validationCtx, client, desktopValidationCommand(), data)
	r.ValidationStep = step
	if err != nil {
		if validationCtx.Err() != nil {
			return r, errors.New("fixed guest desktop validation timed out")
		}
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			switch code := exit.ExitStatus(); code {
			case 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25:
				return r, fmt.Errorf("fixed guest desktop validation failed at step %d", code)
			}
		}
		return r, errors.New("fixed guest desktop validation failed")
	}
	r, err = validateRenderReport(out)
	r.ValidationStep = step
	return r, err
}
