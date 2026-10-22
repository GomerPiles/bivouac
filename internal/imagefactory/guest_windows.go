//go:build windows

package imagefactory

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/hcs"
	"github.com/GomerPiles/bivouac/internal/hvsock"
	"github.com/GomerPiles/bivouac/internal/winguest"
	"golang.org/x/crypto/ssh"
)

// initializeDrivers ports the spike protocol; production Initialize deliberately
// declines these copies. Keep the connection alive through guest preparation.
func initializeDrivers(ctx context.Context, conn net.Conn, drivers []string, key []byte) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	reader := bufio.NewReaderSize(conn, 4096)
	read := func() (string, error) {
		d := time.Now().Add(30 * time.Second)
		if end, ok := ctx.Deadline(); ok && end.Before(d) {
			d = end
		}
		if conn.SetReadDeadline(d) != nil {
			return "", errors.New("agent deadline unavailable")
		}
		b, err := reader.ReadSlice('\n')
		if err != nil {
			return "", errors.New("bounded guest agent line unavailable")
		}
		return strings.TrimSpace(string(b)), nil
	}
	write := func(s string) error {
		if conn.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil {
			return errors.New("agent write deadline unavailable")
		}
		_, err := io.WriteString(conn, s)
		if err != nil {
			return errors.New("agent request failed")
		}
		return nil
	}
	gpu := func() error {
		var b strings.Builder
		fmt.Fprintf(&b, "gpu_query_response:%d\n", len(drivers))
		for i, d := range drivers {
			fmt.Fprintf(&b, "AppSandbox.Drv.%d|C:\\Windows\\System32\\HostDriverStore\\FileRepository\\%s|\n", i, filepath.Base(d))
		}
		return write(b.String())
	}
	hello, err := read()
	if err != nil || hello != "hello" {
		return errors.New("guest agent greeting unavailable")
	}
	if err = gpu(); err != nil {
		return err
	}
	if err = write("1:ssh_enable\n"); err != nil {
		return err
	}
	keySent, keyReady, vddAbsent, gpuReady := false, false, false, false
	for readBytes, lines := 0, 0; readBytes < 1<<20 && lines < 4096; lines++ {
		line, err := read()
		if err != nil {
			return err
		}
		readBytes += len(line) + 1
		switch line {
		case "gpu_query":
			if err = gpu(); err != nil {
				return err
			}
		case "ssh_ready", "1:ssh_ready":
			if !keySent {
				if err = write("ssh_deploy_key " + string(key) + "\n"); err != nil {
					return err
				}
				keySent = true
			}
		case "ssh_key_deployed":
			if !keySent {
				return errors.New("unsolicited key acknowledgement")
			}
			keyReady = true
		case "ssh_failed", "1:ssh_failed", "ssh_key_failed", "service_stopping", "os_shutdown":
			return errors.New("guest agent initialization failed")
		}
		if strings.HasPrefix(line, "idd_status:") {
			if line != "idd_status:not_found" {
				return errors.New("guest agent did not confirm VDD absence")
			}
			vddAbsent = true
		}
		if line == "hyperv_video:disabled" {
			return errors.New("guest agent disabled synthetic video")
		}
		if strings.HasPrefix(line, "gpu_copy_error:") || strings.HasPrefix(line, "gpu_device_failed:") {
			return errors.New("guest GPU driver copy failed")
		}
		if count, ok := strings.CutPrefix(line, "gpu_copy_done:"); ok {
			n, e := strconv.ParseUint(count, 10, 32)
			if e != nil || n > 8192 {
				return errors.New("invalid GPU copy count")
			}
			gpuReady = true
		}
		if keyReady && vddAbsent && gpuReady {
			return nil
		}
	}
	return errors.New("guest agent transcript exceeds bound")
}

func dialGuest(ctx context.Context, runtimeID, service string) (net.Conn, error) {
	vm, err := hvsock.ParseGUID(runtimeID)
	if err != nil {
		return nil, err
	}
	svc, err := hvsock.ParseGUID(service)
	if err != nil {
		return nil, err
	}
	for {
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, e := hvsock.Dial(attempt, hvsock.Addr{VMID: vm, ServiceID: svc})
		cancel()
		if e == nil {
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("guest service connection timed out")
		case <-time.After(time.Second):
		}
	}
}
func prepareGuest(ctx context.Context, api *hcs.API, c Config, r *record) error {
	identity, err := winguest.NewIdentity()
	if err != nil {
		return err
	}
	defer identity.Clear()
	conn, err := dialGuest(ctx, r.RuntimeID, winguest.AgentService)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err = initializeDrivers(ctx, conn, c.Drivers, identity.PublicKey); err != nil {
		return err
	}
	transport, err := dialGuest(ctx, r.RuntimeID, winguest.SSHService)
	if err != nil {
		return err
	}
	defer func() { _ = transport.Close() }()
	client, _, err := winguest.Connect(ctx, transport, c.GuestUser, identity, func(string) error {
		s, e := api.Open(ctx, r.Name)
		if e != nil {
			return errors.New("build guest identity unavailable")
		}
		defer s.Close()
		p, e := s.Properties(ctx)
		if e != nil {
			return e
		}
		return prove(r, p, true)
	})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	data := map[string]any{"name": r.Name, "user": c.GuestUser, "sha256": r.Manifest.ProbeSHA256, "script_sha256": r.Manifest.ValidationSHA256, "autologon_sha256": r.Manifest.AutologonSHA256, "require_setup": true, "prepared": false}
	b, err := guestRun(ctx, client, validateEntry, data)
	if err != nil {
		return errors.Join(errors.New("guest desktop validation failed"), err)
	}
	var topology winguest.Topology
	if json.Unmarshal(b, &topology) != nil {
		return errors.New("invalid topology report")
	}
	r.Manifest.Topology = &topology
	if err := factoryDisplayReportOK(b); err != nil {
		return err
	}
	// VersionInfo reads no runner credentials and does not start the listener.
	b, err = guestRun(ctx, client, `param($data);$helper='C:\Windows\AppSandbox\hcs-runner-check.ps1';if((Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash -ine $data.runner_check_sha256){exit 14};. $helper;if(!(Assert-CleanRunner 'C:\actions-runner')){exit 1};$v=(Get-Item -LiteralPath 'C:\actions-runner\bin\Runner.Listener.exe').VersionInfo.ProductVersion;if($v -match '^\d{1,4}\.\d{1,4}\.\d{1,4}$'){[Console]::Out.Write($v)}`, map[string]string{"runner_check_sha256": hashBytes([]byte(runnerCheck))})
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
	b, err = guestRun(ctx, client, sanitizeEntry, data)
	if err != nil || string(b) != "sanitized-shutdown-scheduled" {
		return errors.New("guest sanitation and shutdown acknowledgement failed")
	}
	return nil
}

func guestRun(ctx context.Context, client *ssh.Client, script string, data any) ([]byte, error) {
	b, err := guestInput(script, data)
	if err != nil {
		return nil, err
	}
	out, err := winguest.Run(ctx, client, "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "+encodedPowerShell(guestBootstrap), b, 8192)
	if err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) && exit.ExitStatus() > 0 && exit.ExitStatus() <= 255 {
			return nil, fmt.Errorf("fixed guest operation exited at step %d", exit.ExitStatus())
		}
		return nil, errors.New("fixed guest operation failed")
	}
	return out, nil
}

func factoryDisplayReportOK(b []byte) error {
	if !renderOK(b) {
		return errors.New("guest desktop rendering checks did not all pass")
	}
	var topology winguest.Topology
	if json.Unmarshal(b, &topology) != nil {
		return errors.New("invalid topology report")
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
