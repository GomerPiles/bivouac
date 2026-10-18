//go:build windows

package hcsspike

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"golang.org/x/crypto/ssh"
)

func serviceID(port uint16) guid.GUID {
	return guid.GUID{Data1: 0xa5b0cafe, Data2: port, Data3: 0x4000, Data4: [8]byte{0x80, 0, 0, 0, 0, 0, 0, 1}}
}

func writeGPU(w io.Writer, c Config) error {
	if !c.GPU || len(c.Drivers) == 0 {
		_, err := io.WriteString(w, "gpu_none\n")
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "gpu_query_response:%d\n", len(c.Drivers))
	for i, driver := range c.Drivers {
		fmt.Fprintf(&b, "%s|%s|\n", shareName(i), driver.GuestPath)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// speakAgent implements only fixed initialization and public-key deployment.
// Guest diagnostic messages are discarded, not logged or copied into errors.
func speakAgent(ctx context.Context, conn net.Conn, c Config, publicKey []byte) (Report, error) {
	var report Report
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	reader := bufio.NewReaderSize(conn, 4096)
	readLine := func() (string, error) {
		deadline := time.Now().Add(30 * time.Second)
		if limit, ok := ctx.Deadline(); ok {
			deadline = minTime(deadline, limit)
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return "", errors.New("guest agent read deadline unavailable")
		}
		b, err := reader.ReadSlice('\n')
		if err != nil {
			return "", errors.New("guest agent line unavailable or exceeds 4 KiB")
		}
		return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
	}
	hello, err := readLine()
	if err != nil {
		return report, err
	}
	if hello != "hello" {
		return report, errors.New("unexpected guest agent greeting")
	}
	report.AgentConnected = true
	deadline := time.Now().Add(10 * time.Second)
	if limit, ok := ctx.Deadline(); ok {
		deadline = minTime(deadline, limit)
	}
	if err = conn.SetWriteDeadline(deadline); err != nil {
		return report, errors.New("guest agent write deadline unavailable")
	}
	if err = writeGPU(conn, c); err != nil {
		return report, errors.New("guest GPU initialization failed")
	}
	if _, err = io.WriteString(conn, "1:ssh_enable\n"); err != nil {
		return report, errors.New("guest SSH initialization failed")
	}
	keySent, keyReady := false, false
	gpuReady := len(c.Drivers) == 0
	bytesRead := 0
	for lines := 0; lines < 4096 && bytesRead < 1<<20; lines++ {
		line, err := readLine()
		if err != nil {
			return report, err
		}
		bytesRead += len(line) + 1
		switch line {
		case "gpu_query":
			if err = conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return report, errors.New("guest agent write deadline unavailable")
			}
			if err = writeGPU(conn, c); err != nil {
				return report, errors.New("guest GPU response failed")
			}
		case "idd_status:ok":
			report.DisplayReady = true
		case "ssh_ready", "1:ssh_ready":
			if !keySent {
				if err = conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
					return report, errors.New("guest agent write deadline unavailable")
				}
				// This is the agent's public-key protocol, not a shell command.
				if _, err = conn.Write(append(append([]byte("ssh_deploy_key "), publicKey...), '\n')); err != nil {
					return report, errors.New("guest public-key deployment failed")
				}
				keySent = true
			}
		case "ssh_key_deployed":
			if !keySent {
				return report, errors.New("unsolicited guest key acknowledgement")
			}
			keyReady = true
		case "ssh_failed", "1:ssh_failed", "ssh_key_failed", "service_stopping", "os_shutdown":
			return report, errors.New("guest agent reported initialization failure")
		}
		if strings.HasPrefix(line, "idd_status:") && line != "idd_status:ok" {
			report.DisplayReady = false
		}
		if strings.HasPrefix(line, "gpu_copy_error:") || strings.HasPrefix(line, "gpu_device_failed:") {
			return report, errors.New("guest GPU preparation failed")
		}
		if strings.HasPrefix(line, "gpu_copy_done:") {
			count, parseErr := strconv.ParseUint(strings.TrimPrefix(line, "gpu_copy_done:"), 10, 32)
			if parseErr != nil || count > 8192 {
				return report, errors.New("invalid bounded guest GPU file count")
			}
			report.GPUFilesCopied = uint32(count)
			gpuReady = true
		}
		if keyReady && report.DisplayReady && gpuReady {
			return report, nil
		}
	}
	return report, errors.New("guest agent transcript exceeded bound")
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (a *native) verify(ctx context.Context, c Config, runtimeID string) error {
	s, err := a.Open(ctx, c.name())
	if err != nil {
		return errors.New("cannot verify native spike identity")
	}
	defer s.Close()
	p, err := s.Properties(ctx)
	if err != nil {
		return err
	}
	if err = proveNative(c, record{RuntimeID: runtimeID}, p); err != nil {
		return err
	}
	if p.State != "Running" {
		return errors.New("native spike VM is no longer running")
	}
	return nil
}

func (a *native) Probe(ctx context.Context, c Config, runtimeID string) (Report, error) {
	var report Report
	vmID, err := guid.FromString(runtimeID)
	if err != nil || vmID == (guid.GUID{}) {
		return report, errors.New("invalid native runtime GUID")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return report, err
	}
	defer clear(private)
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return report, errors.New("cannot create ephemeral SSH identity")
	}
	public := []byte(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
	started := time.Now()
	var conn *winio.HvsockConn
	for {
		if err = a.verify(ctx, c, runtimeID); err != nil {
			return report, err
		}
		dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err = winio.Dial(dialCtx, &winio.HvsockAddr{VMID: vmID, ServiceID: serviceID(1)})
		cancel()
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return report, errors.New("guest agent did not become reachable within the trial budget")
		case <-time.After(500 * time.Millisecond):
		}
	}
	defer func() { _ = conn.Close() }()
	connectMS := elapsedMS(started)
	started = time.Now()
	report, err = speakAgent(ctx, conn, c, public)
	report.TimingsMS.Guest.AgentConnectMS = connectMS
	report.TimingsMS.Guest.AgentInitializeMS = elapsedMS(started)
	if err != nil {
		return report, err
	}
	if err = a.verify(ctx, c, runtimeID); err != nil {
		return report, err
	}
	started = time.Now()
	sshCtx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	transport, err := winio.Dial(sshCtx, &winio.HvsockAddr{VMID: vmID, ServiceID: serviceID(7)})
	if err != nil {
		return report, errors.New("offline HvSocket SSH connection failed")
	}
	defer func() { _ = transport.Close() }()
	stop := context.AfterFunc(sshCtx, func() { _ = transport.Close() })
	defer stop()
	deadline, _ := sshCtx.Deadline()
	if err = transport.SetDeadline(deadline); err != nil {
		return report, errors.New("SSH transport deadline unavailable")
	}
	config := &ssh.ClientConfig{
		User: c.GuestUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		// The first key is accepted only from the freshly owned runtime's
		// fixed HvSocket endpoint. There is no network address or key reuse.
		HostKeyCallback: func(_ string, _ net.Addr, _ ssh.PublicKey) error { return a.verify(sshCtx, c, runtimeID) },
	}
	clientConn, channels, requests, err := ssh.NewClientConn(transport, "hcs-spike", config)
	if err != nil {
		return report, errors.New("ephemeral SSH authentication failed")
	}
	client := ssh.NewClient(clientConn, channels, requests)
	defer func() { _ = client.Close() }()
	report.TimingsMS.Guest.SSHAuthenticateMS = elapsedMS(started)
	report.SSHAuthenticated = true
	started = time.Now()
	err = checkSSHExecution(sshCtx, client, &report)
	report.TimingsMS.Guest.SSHChecksMS = elapsedMS(started)
	if err != nil {
		return report, err
	}
	if c.RenderProbe != nil {
		if err = a.verify(ctx, c, runtimeID); err != nil {
			return report, err
		}
		started = time.Now()
		observed, renderErr := validateDesktop(sshCtx, client, c)
		report.TimingsMS.Guest.DesktopValidateMS = elapsedMS(started)
		report.TimingsMS.Guest.ConsoleWaitMS = observed.consoleWaitMS
		report.TimingsMS.Guest.GPUDeviceWaitMS = observed.gpuDeviceWaitMS
		report.TimingsMS.Guest.InteractiveProbeMS = observed.interactiveProbeMS
		report.GuestValidationStep = observed.ValidationStep
		report.GuestReady = observed.GuestReady
		report.DesktopReady = observed.DesktopReady
		report.HardwareD3D11 = observed.HardwareD3D11
		report.Presented = observed.Presented
		report.PixelReadback = observed.PixelReadback
		report.RenderStage = observed.Stage
		report.RenderHRESULT = observed.HRESULT
		report.RenderVendorID = observed.VendorID
		report.RenderDeviceID = observed.DeviceID
		report.RenderAdapterCount = observed.AdapterCount
		report.RenderHardwareAdapterCount = observed.HardwareAdapterCount
		report.RenderDefaultVendorID = observed.DefaultVendorID
		report.RenderDefaultDeviceID = observed.DefaultDeviceID
		report.GPUDeviceDiagnosticsValid = observed.GPUDeviceDiagnosticsValid
		report.DisplayDeviceCount = observed.DisplayDeviceCount
		report.VirtualRenderDeviceCount = observed.VirtualRenderDeviceCount
		report.VirtualRenderProblemCode = observed.VirtualRenderProblemCode
		return report, renderErr
	}
	return report, nil
}
