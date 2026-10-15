//go:build windows

package hcsspike

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/ssh"
)

//go:embed guest_validate.ps1
var guestValidate string

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
func validateDesktop(ctx context.Context, client *ssh.Client, c Config) (renderResult, error) {
	var r renderResult
	probe, err := readPinned(*c.RenderProbe)
	if err != nil {
		return r, err
	}
	data, err := json.Marshal(map[string]any{"name": c.name(), "user": c.GuestUser, "probe": probe, "sha256": c.RenderProbe.SHA256, "require_setup": len(c.SetupAssets) != 0})
	if err != nil {
		return r, err
	}
	session, err := client.NewSession()
	if err != nil {
		return r, errors.New("cannot create guest validation SSH session")
	}
	defer func() { _ = session.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stop()
	var out boundedOutput
	session.Stdin = bytes.NewReader(data)
	session.Stdout = &out
	session.Stderr = io.Discard
	// Fixed code only. Name, account and executable bytes arrive as JSON data.
	err = session.Run("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encodedPowerShell(guestValidate))
	if err != nil {
		return r, errors.New("fixed guest desktop validation failed")
	}
	return validateRenderReport(out.data)
}
