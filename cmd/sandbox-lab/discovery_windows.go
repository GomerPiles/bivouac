//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/Microsoft/go-winio/pkg/guid"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type discoveryReport struct {
	Identity labRecord `json:"identity"`
	KVP64    string    `json:"kvp64,omitempty"`
	KVP32    string    `json:"kvp32,omitempty"`
	SMBIOS   string    `json:"smbios,omitempty"`
	HvLocal  string    `json:"hv_local,omitempty"`
}

// Only validated UUIDs leave the guest. Do not enumerate host-identifying KVP
// data or include registry/WMI error text in public reports.
func guestDiscovery(ctx context.Context) error {
	if !session().valid() {
		return errors.New("discovery guest context refused")
	}
	var identity labRecord
	if readJSON(filepath.Join(guestLabDirectory, "identity.json"), &identity) != nil || !identity.valid() || identity.Phase != "started" || identity.Boot == "" {
		return errors.New("discovery guest identity refused")
	}
	report := discoveryReport{Identity: identity}
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\HvSocket\Addresses`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		if value, _, err := key.GetStringValue("LocalAddress"); err == nil {
			value = strings.ToLower(strings.Trim(value, "{}"))
			if validGUID(value) {
				report.HvLocal = value
			}
		}
		if value, _, err := key.GetBinaryValue("LocalAddress"); err == nil && len(value) == 16 {
			var raw [16]byte
			copy(raw[:], value)
			id := guid.FromWindowsArray(raw).String()
			if validGUID(id) {
				report.HvLocal = id
			}
		}
		_ = key.Close()
	}
	for _, view := range []struct {
		flag   uint32
		target *string
	}{{registry.WOW64_64KEY, &report.KVP64}, {registry.WOW64_32KEY, &report.KVP32}} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`, registry.QUERY_VALUE|view.flag)
		if err != nil {
			continue
		}
		value, _, err := key.GetStringValue("VirtualMachineId")
		_ = key.Close()
		value = strings.ToLower(strings.Trim(value, "{}"))
		if err == nil && validGUID(value) {
			*view.target = value
		}
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return errors.New("discovery system directory unavailable")
	}
	const script = `(Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop).UUID | ConvertTo-Json -Compress`
	command := exec.CommandContext(ctx, filepath.Join(system, `WindowsPowerShell\v1.0\powershell.exe`), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var output boundedBuffer
	command.Stdout = &output
	if command.Run() == nil {
		var value string
		if json.Unmarshal(output.data, &value) == nil && validGUID(value) {
			report.SMBIOS = strings.ToLower(value)
		}
	}
	return writeReport("discovery.json", report)
}

type discoveryAttempt struct {
	Source    string `json:"source"`
	Exposed   bool   `json:"exposed"`
	Connected bool   `json:"connected"`
	Bound     bool   `json:"bound"`
	Code      uint32 `json:"code,omitempty"`
}

// A failed route never authorizes adoption or a shared configuration change.
func (h *labHost) discoveryProbe(ctx context.Context, result *labResult) error {
	data, err := h.call(ctx, "exec", "--id", h.record.ID, "--command", `"C:\Program Files\Bivouac\sandbox-lab.exe" guest-discovery`, "--run-as", "ExistingLogin")
	var receipt struct {
		Exit *int `json:"ExitCode"`
	}
	if err != nil || decodeBounded(bytes.NewReader(data), &receipt) != nil || receipt.Exit == nil || *receipt.Exit != 0 {
		return errors.New("guest discovery dispatch unproven")
	}
	var report discoveryReport
	if readJSON(filepath.Join(h.output, "discovery.json"), &report) != nil || !sameGuest(report.Identity, h.record) {
		return errors.New("guest discovery identity refused")
	}
	for _, candidate := range []struct{ source, value string }{{"kvp64", report.KVP64}, {"kvp32", report.KVP32}, {"smbios", report.SMBIOS}, {"hv_local", report.HvLocal}} {
		attempt := discoveryAttempt{Source: candidate.source, Exposed: candidate.value != ""}
		if candidate.value != "" {
			raw, err := nativeRaw(candidate.value)
			if err != nil {
				return errors.New("guest discovery route malformed")
			}
			step, cancel := context.WithTimeout(ctx, 5*time.Second)
			conn, dialErr := raw(step)
			if conn != nil {
				attempt.Connected = true
				_ = conn.Close()
			}
			if dialErr != nil {
				var code windows.Errno
				if errors.As(dialErr, &code) {
					attempt.Code = uint32(code)
				}
			} else {
				var output boundedBuffer
				var identity labRecord
				attempt.Bound = guestagent.Run(step, raw, []string{guestBinary, "identity"}, nil, &output) == nil && decodeBounded(bytes.NewReader(output.data), &identity) == nil && sameGuest(identity, h.record)
			}
			cancel()
		}
		result.Discovery = append(result.Discovery, attempt)
	}
	result.DiscoveryChecked = true
	return nil
}
