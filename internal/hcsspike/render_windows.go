//go:build windows

package hcsspike

import (
	"bytes"
	"context"
	_ "embed"
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
// growth. Both the embedded script and its data are sent as JSON on stdin.
const guestValidateBootstrap = `$ErrorActionPreference='Stop';try{$line=[Console]::In.ReadLine();if(!$line -or $line.Length -gt 100000000){exit 18};$p=$line|ConvertFrom-Json;& ([ScriptBlock]::Create($p.script)) $p.data}catch{exit 18}`

func desktopValidationCommand() string {
	return "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encodedPowerShell(guestValidateBootstrap)
}

type renderResult struct {
	GuestReady    bool   `json:"guest_ready"`
	DesktopReady  bool   `json:"desktop_ready"`
	HardwareD3D11 bool   `json:"hardware_d3d11"`
	Presented     bool   `json:"presented"`
	PixelReadback bool   `json:"pixel_readback"`
	Stage         uint32 `json:"stage"`
	HRESULT       uint32 `json:"hresult"`
	VendorID      uint32 `json:"vendor_id"`
	DeviceID      uint32 `json:"device_id"`
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
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
		return r, errors.New("invalid bounded guest rendering report")
	}
	if !r.GuestReady || !r.DesktopReady || !r.HardwareD3D11 || !r.Presented || !r.PixelReadback || r.Stage != 7 || r.HRESULT != 0 || r.VendorID == 0 || (r.VendorID == 0x1414 && r.DeviceID == 0x8c) {
		return r, errors.New("guest rendering checks did not all pass")
	}
	return r, nil
}

// A timed-out SSH request closes the owned client, including requests that
// have not yet acknowledged session/command creation. No command is replayed.
func runGuestSSH(ctx context.Context, client *ssh.Client, command string, input []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()
	var out boundedOutput
	session.Stdin = bytes.NewReader(input)
	session.Stdout = &out
	session.Stderr = io.Discard
	err = session.Run(command)
	return out.data, err
}

func guestScriptInput(script string, data any) ([]byte, error) {
	input, err := json.Marshal(map[string]any{"script": script, "data": data})
	if err != nil {
		return nil, err
	}
	return append(input, '\n'), nil
}

func checkSSHExecution(ctx context.Context, client *ssh.Client, report *Report) error {
	commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	command := "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encodedPowerShell(`[Console]::Out.Write('ready')`)
	out, err := runGuestSSH(commandCtx, client, command, nil)
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
	out, err = runGuestSSH(stdinCtx, client, desktopValidationCommand(), input)
	cancel()
	if err != nil || string(out) != "ready" {
		return errors.New("fixed SSH framed-stdin check failed")
	}
	report.SSHStdinReady = true
	return nil
}

func validateDesktop(ctx context.Context, client *ssh.Client, c Config) (renderResult, error) {
	var r renderResult
	probe, err := readPinned(*c.RenderProbe)
	if err != nil {
		return r, err
	}
	data, err := guestScriptInput(guestValidate, map[string]any{"name": c.name(), "user": c.GuestUser, "probe": probe, "sha256": c.RenderProbe.SHA256, "require_setup": len(c.SetupAssets) != 0})
	if err != nil {
		return r, err
	}
	// Readiness has a three-minute bound and the interactive probe at most fifty
	// seconds; leave transfer/startup headroom while keeping the trial deadline.
	validationCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	out, err := runGuestSSH(validationCtx, client, desktopValidationCommand(), data)
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
	return validateRenderReport(out)
}
