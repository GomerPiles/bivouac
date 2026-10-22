//go:build windows

package imagefactory

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/winguest"
)

func TestDisplayMediaAndManifest(t *testing.T) {
	c := testConfig()
	r := &record{Name: "bivouac-aaaaaaa", Workspace: t.TempDir(), Manifest: Manifest{Assets: map[string]string{}, Topology: &winguest.Topology{ActiveDisplays: 1}}}
	copyFile := func(_ context.Context, _, _, pin string, _ int64) (int64, string, error) { return 1, pin, nil }
	run := func(_ context.Context, _ string, input any, _ bool) ([]byte, error) {
		content := input.(map[string]string)["specialize"]
		if content != guestSpecialize+disableFirstLogonAnimation || strings.Contains(content, "$display") {
			t.Fatal("specialize retained mode selection")
		}
		return nil, nil
	}
	if err := prepareMediaWith(t.Context(), c, r, func(p string) error { return os.Mkdir(p, 0700) }, copyFile, run); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r.Workspace, "setup-assets", "DISPLAY.JSON")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("display selection asset retained", err)
	}
	b, err := json.Marshal(r.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.Unmarshal(b, &fields) != nil {
		t.Fatal("manifest JSON")
	}
	if _, present := fields["display"]; present {
		t.Fatal("manifest mode retained")
	}
	if _, present := fields["topology"]; !present {
		t.Fatal("manifest topology lost")
	}
}

func TestFactoryDisplayTranscripts(t *testing.T) {
	for _, test := range []struct {
		name, lines string
		ack, pass   bool
	}{
		{"success", "idd_status:not_found", true, true},
		{"VDD present", "idd_status:ok", true, false},
		{"error", "idd_status:error", true, false},
		{"unknown", "idd_status:guest-private-output", true, false},
		{"disabled", "hyperv_video:disabled\nidd_status:not_found", true, false},
		{"no key ack", "idd_status:not_found", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			host, guest := net.Pipe()
			defer func() { _ = host.Close() }()
			done := make(chan error, 1)
			go func() {
				defer func() { _ = guest.Close() }()
				_, err := io.WriteString(guest, "hello\n")
				reader := bufio.NewReader(guest)
				for range 3 {
					if err == nil {
						_, err = reader.ReadString('\n')
					}
				}
				if err == nil {
					_, err = io.WriteString(guest, "ssh_ready\n")
				}
				if err == nil {
					var key string
					key, err = reader.ReadString('\n')
					if err == nil && key != "ssh_deploy_key public-key\n" {
						err = errors.New("key frame")
					}
				}
				if err == nil {
					text := "gpu_copy_done:0\n" + test.lines + "\n"
					if test.ack {
						text += "ssh_key_deployed\n"
					}
					_, err = io.WriteString(guest, text)
				}
				if err == nil {
					_, _ = io.Copy(io.Discard, guest)
				}
				done <- err
			}()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err := initializeDrivers(ctx, host, testConfig().Drivers, []byte("public-key"))
			_ = host.Close()
			if guestErr := <-done; guestErr != nil && !errors.Is(guestErr, io.ErrClosedPipe) {
				t.Fatal(guestErr)
			}
			if (err == nil) != test.pass || (err != nil && strings.Contains(err.Error(), "guest-private-output")) {
				t.Fatal("factory agent contract", err)
			}
		})
	}
}

func TestFactoryDisplayReportGates(t *testing.T) {
	base := map[string]any{"guest_ready": true, "desktop_ready": true, "hardware_d3d11": true, "presented": true, "pixel_readback": true, "stage": 7, "hresult": 0, "vendor_id": 0x1002, "device_id": 1, "adapter_count": 2, "hardware_adapter_count": 1, "gpu_device_diagnostics_valid": true, "display_device_count": 2, "virtual_render_device_count": 1, "virtual_render_problem_code": 0}
	b, _ := json.Marshal(base)
	if factoryDisplayReportOK(b) == nil {
		t.Fatal("missing topology accepted")
	}
	for key, value := range map[string]any{"topology_valid": true, "active_display_count": 1, "primary_display_count": 1, "primary_width": 1024, "primary_height": 768, "virtual_equals_primary": true, "primary_adapter_kind": 1, "vdd_node_count": 0, "hyperv_video_enabled": true, "hyperv_video_started": true} {
		base[key] = value
	}
	b, _ = json.Marshal(base)
	if factoryDisplayReportOK(b) != nil {
		t.Fatal("synthetic report refused")
	}
	for key, value := range map[string]any{"active_display_count": 3, "primary_display_count": 0, "primary_adapter_kind": 2, "vdd_node_count": 1, "hyperv_video_enabled": false, "hyperv_video_started": false, "pixel_readback": false} {
		previous := base[key]
		base[key] = value
		b, _ = json.Marshal(base)
		if factoryDisplayReportOK(b) == nil {
			t.Fatal("failed gate accepted", key)
		}
		base[key] = previous
	}
}

// Parse the nested interactive script, compile its C# type and exercise the
// hardware-ID classifier with fixtures. No probe, native display function,
// scheduled task, service, registry lookup or UI operation is executed.
func TestTopologyProbeCompiles(t *testing.T) {
	input, _ := json.Marshal(guestValidate)
	script := `$ErrorActionPreference='Stop'
$text=[Console]::In.ReadToEnd()|ConvertFrom-Json
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
if($errors.Count){exit 1}
$nested=$ast.Find({param($n)$n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value.Contains('public static class DesktopProbe')},$true)
if(!$nested){exit 2}
$ast=[Management.Automation.Language.Parser]::ParseInput($nested.Value,[ref]$tokens,[ref]$errors)
if($errors.Count){exit 3}
$source=$ast.Find({param($n)$n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value.TrimStart().StartsWith('using System;')},$true)
if(!$source){exit 4}
Add-Type -TypeDefinition $source.Value -ReferencedAssemblies @('System.Windows.Forms','System.Drawing')
$kind=[DesktopProbe].GetMethod('PrimaryAdapterKind',([Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static))
if(!$kind){exit 7}
# An invalid registry key proves that a supplied ID never attempts the fallback.
$invalidKey='\Registry\Machine\'+[char]0
foreach($case in @(
 @{id='VMBUS\{DA0A7802-0000-0000-0000-000000000000}';expected=1},
 @{id='vmbus\{da0a7802-0000-0000-0000-000000000000}';expected=1},
 @{id='ROOT\APPSANDBOXVDD';expected=2},
 @{id='root\appsandboxvdd';expected=2},
 @{id='ROOT\APPSANDBOXVDD\unmatched';expected=3},
 @{id='PCI\OTHER';expected=3}
)){
 if($kind.Invoke($null,[object[]]@($case.id,$invalidKey)) -ne $case.expected){exit 8}
}
if($kind.Invoke($null,[object[]]@('',$null)) -ne 3 -or $kind.Invoke($null,[object[]]@($null,$null)) -ne 3){exit 9}
$inputType=[DesktopProbe].GetNestedType('Input',[Reflection.BindingFlags]::NonPublic)
if([Runtime.InteropServices.Marshal]::SizeOf([Activator]::CreateInstance($inputType)) -ne 40){exit 5}
$f=[DesktopFacts]::new()
$f | Add-Member -NotePropertyName vdd_node_count -NotePropertyValue ([uint32]0)
$json=$f|ConvertTo-Json -Compress
if($json.Length -gt 4096 -or !($json.Contains('"active_display_count":0')) -or !($json.Contains('"vdd_node_count":0'))){exit 6}
[Console]::Out.Write('compiled')`
	if got := runTestPS(t, script, input); got != "compiled" {
		t.Fatal("nested topology probe")
	}
}
