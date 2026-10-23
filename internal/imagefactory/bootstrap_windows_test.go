//go:build windows

package imagefactory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/windesktop"
	"golang.org/x/sys/windows"
)

// Exercise the real agent process launcher as the current user. No RunCLI
// session gate, HvSocket listener, guest, task or service is involved.
type localAgentListener struct {
	connections chan io.ReadWriteCloser
	closed      chan struct{}
}

func (l *localAgentListener) Accept() (io.ReadWriteCloser, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *localAgentListener) Close() error { close(l.closed); return nil }

func localAgent(t *testing.T) guestagent.Dialer {
	t.Helper()
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Skip("powershell.exe unavailable")
	}
	// Keep PowerShell module-analysis and cmdletization caches in the fixture.
	temp := t.TempDir()
	t.Setenv("PSModuleAnalysisCachePath", filepath.Join(temp, "ModuleAnalysisCache"))
	t.Setenv("TEMP", temp)
	t.Setenv("TMP", temp)
	ctx, cancel := context.WithCancel(t.Context())
	l := &localAgentListener{connections: make(chan io.ReadWriteCloser), closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- guestagent.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error("local agent failed")
		}
	})
	return func(ctx context.Context) (net.Conn, error) {
		host, peer := net.Pipe()
		select {
		case l.connections <- peer:
			return host, nil
		case <-ctx.Done():
			_ = host.Close()
			_ = peer.Close()
			return nil, ctx.Err()
		}
	}
}

func runBootstrap(t *testing.T, dial guestagent.Dialer, bootstrap, script string, data any) ([]byte, error) {
	t.Helper()
	input, err := guestInput(script, data)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var out boundedGuestOutput
	err = guestagent.Run(ctx, dial, []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedPowerShell(bootstrap)}, bytes.NewReader(input), &out)
	return out.data, err
}

const consoleReport = `param($data);if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){exit 19};[Console]::Out.Write(($data.report|ConvertTo-Json -Compress -Depth 3));[Console]::Out.Flush()`

func TestGuestBootstrapOutput(t *testing.T) {
	dial := localAgent(t)
	module := filepath.Join(t.TempDir(), "OutputFixture.psm1")
	// Deterministic first-import host output, in addition to the inbox module's
	// read-only absent-task lookup. Only the temporary module is written.
	noise := `Write-Output 'incidental-pipeline';Write-Host 'incidental-host';Write-Warning 'incidental-warning';Write-Verbose 'incidental-verbose' -Verbose;$DebugPreference='Continue';Write-Debug 'incidental-debug';Write-Information 'incidental-information' -InformationAction Continue;Write-Progress -Activity 'incidental-progress' -PercentComplete 1;`
	if err := os.WriteFile(module, []byte(noise), 0600); err != nil {
		t.Fatal(err)
	}
	report := map[string]any{
		"guest_ready": true, "desktop_ready": true, "hardware_d3d11": true, "presented": true, "pixel_readback": true,
		"stage": 7, "hresult": 0, "vendor_id": 4098, "device_id": 1, "adapter_count": 2, "hardware_adapter_count": 1,
		"gpu_device_diagnostics_valid": true, "display_device_count": 2, "virtual_render_device_count": 1, "virtual_render_problem_code": 0,
		"topology_valid": true, "active_display_count": 1, "primary_display_count": 1, "primary_width": 1024, "primary_height": 768,
		"virtual_equals_primary": true, "primary_adapter_kind": 1, "vdd_node_count": 0, "hyperv_video_enabled": true, "hyperv_video_started": true,
		"encoding_probe": "\u00e9\u4e2d",
	}
	data := map[string]any{"report": report, "module": module}
	script := `param($data);Import-Module -Name $data.module;Get-ScheduledTask -TaskName 'bivouac-absent-output-test' -ErrorAction SilentlyContinue;` + noise + `& {` + consoleReport + `} $data;` + noise
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	output, err := guestRun(ctx, dial, script, data)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(report)
	var got map[string]any
	if json.Unmarshal(output, &got) != nil {
		t.Fatal("incidental output reached report")
	}
	canonical, _ := json.Marshal(got)
	if !bytes.Equal(want, canonical) || factoryDisplayReportOK(output) != nil {
		t.Fatal("report changed")
	}
	t.Logf("real report len=%d", len(output))
	acknowledgements := make(map[string][]byte)
	for _, ack := range []string{"2.300.0", "sanitized-shutdown-scheduled"} {
		b, err := guestRun(ctx, dial, `param($data);`+noise+`[Console]::Out.Write($data);`+noise+`exit 0`, ack)
		if err != nil || string(b) != ack {
			t.Fatalf("acknowledgement len=%d want_len=%d err=%v", len(b), len(ack), err)
		}
		acknowledgements[ack] = b
	}
	assignmentOnly := strings.Replace(guestBootstrap, " 1>$null", "", 1)
	b, err := runBootstrap(t, dial, assignmentOnly, `param($data);'incidental-pipeline';[Console]::Out.Write($data);'incidental-pipeline';exit 0`, "2.300.0")
	if err != nil || string(b) == "2.300.0" {
		t.Fatal("exit control did not reproduce assignment-only contamination")
	}
	t.Logf("assignment-only exit len=%d want_len=7", len(b))
	for _, layout := range []struct{ frame, write int }{{1, 1}, {7, 11}, {7, 0}, {32768, 0}} {
		t.Run(fmt.Sprintf("frame%d_write%d", layout.frame, layout.write), func(t *testing.T) {
			framed := fakeFactoryAgentFrames(func(_ []string, input []byte) ([]byte, int) {
				if len(input) == 0 {
					return nil, 0
				} // agent version proof
				var payload struct{ Script string }
				if len(input) < 4 || json.Unmarshal(input[4:], &payload) != nil {
					return nil, 18
				}
				switch payload.Script {
				case validateEntry:
					return output, 0
				case sanitizeEntry:
					return acknowledgements["sanitized-shutdown-scheduled"], 0
				default:
					return acknowledgements["2.300.0"], 0
				}
			}, layout.frame, layout.write)
			r := &record{}
			if err := prepareGuestWithDial(t.Context(), testConfig(), r, framed); err != nil || r.Manifest.Topology == nil || !r.Manifest.Topology.SyntheticOK() || r.Manifest.RunnerVersion != "2.300.0" {
				t.Fatal("real report changed in framing or production decoding")
			}
		})
	}
	// Removing the producer guard reproduces contamination under the same native
	// launcher. This control prevents the fixture from silently losing its noise.
	unguarded := strings.Replace(guestBootstrap, "$null = &", "&", 1)
	unguarded = strings.Replace(unguarded, " 1>$null 3>$null 4>$null 5>$null 6>$null", "", 1)
	b, err = runBootstrap(t, dial, unguarded, script, data)
	if err != nil || json.Valid(b) {
		t.Fatal("unguarded control did not reproduce contamination")
	}
	var topology windesktop.Topology
	err = json.Unmarshal(b, &topology)
	t.Log("unguarded " + reportShape(b, err))
}

func TestGuestBootstrapSyntax(t *testing.T) {
	for _, shell := range []string{"powershell.exe", "pwsh.exe"} {
		t.Run(shell, func(t *testing.T) {
			path, err := exec.LookPath(shell)
			if err != nil {
				t.Skip("PowerShell unavailable")
			}
			text, _ := json.Marshal(guestBootstrap)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, path, "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedPowerShell(`$s=[Console]::In.ReadToEnd()|ConvertFrom-Json;$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e);if($e.Count){exit 1}`))
			cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
			cmd.Stdin = bytes.NewReader(text)
			if err := cmd.Run(); err != nil {
				t.Fatal("bootstrap syntax invalid")
			}
		})
	}
}

func TestGuestBootstrapExitContracts(t *testing.T) {
	dial := localAgent(t)
	for _, code := range []int{1, 11, 14, 18, 25, 29, 37, 255} {
		_, err := guestRun(t.Context(), dial, fmt.Sprintf("exit %d", code), nil)
		if err == nil || err.Error() != fmt.Sprintf("fixed guest operation exited at step %d", code) {
			t.Fatal("exit contract changed")
		}
	}
	_, err := guestRun(t.Context(), dial, `throw 'private-error'`, nil)
	if err == nil || err.Error() != "fixed guest operation exited at step 18" {
		t.Fatal("exception contract changed")
	}
	for _, input := range [][]byte{{0, 0, 0, 0}, {1, 0, 1, 0}, {4, 0, 0, 0, '{'}} {
		var out bytes.Buffer
		err := guestagent.Run(t.Context(), dial, []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedPowerShell(guestBootstrap)}, bytes.NewReader(input), &out)
		var exit *guestagent.ExitError
		if !errors.As(err, &exit) || exit.Code != 18 || out.Len() != 0 {
			t.Fatal("frame rejection changed")
		}
	}
}

func TestRealReportShapeFailures(t *testing.T) {
	dial := localAgent(t)
	numbersOnly := regexp.MustCompile(`^(?:[a-z0-9_]+=(?:[0-9]+|0x[0-9a-f]+) ?)+$`)
	for _, tc := range []struct{ name, script, shape string }{
		{"empty", ``, "len=0 bom=0 nul=0 utf8=1 json=0"},
		{"prefix", `[Console]::Out.Write('private-prefix{}')`, "syntax_offset=1"},
		{"suffix", `[Console]::Out.Write('{}private-suffix')`, "syntax_offset=3"},
		{"second-value", `[Console]::Out.Write('{}{}')`, "syntax_offset=3"},
		{"bom", `[Console]::Out.Write([char]0xfeff+'{}')`, "bom=1"},
		{"utf16", `$o=[Console]::OpenStandardOutput();$b=[Text.Encoding]::Unicode.GetBytes('{}');$o.Write($b,0,$b.Length)`, "nul=2"},
		{"utf16bom", `$o=[Console]::OpenStandardOutput();$b=[byte[]]@(255,254,123,0,125,0);$o.Write($b,0,$b.Length)`, "bom=2"},
		{"invalid-utf8", `$o=[Console]::OpenStandardOutput();$b=[byte[]]@(255,123,125);$o.Write($b,0,$b.Length)`, "utf8=0"},
		{"type", `[Console]::Out.Write('{"topology_valid":"private-value"}')`, "field=1 json_kind=3"},
		{"root", `[Console]::Out.Write('[]')`, "field=0 json_kind=4"},
		{"overflow", `[Console]::Out.Write('{"active_display_count":12345678901234567890}')`, "field=2 json_kind=2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := guestRun(t.Context(), dial, tc.script, nil)
			if err != nil {
				t.Fatal(err)
			}
			var topology windesktop.Topology
			err = json.Unmarshal(b, &topology)
			if err == nil {
				t.Fatal("malformed report accepted")
			}
			shape := reportShape(b, err)
			if !numbersOnly.MatchString(shape) || !strings.Contains(shape, tc.shape) {
				t.Fatal("unsafe or incomplete report shape")
			}
			t.Log(shape)
			// Use the production preparation decoder, not just a test unmarshal.
			fake := fakeFactoryAgent(func([]string, []byte) ([]byte, int) { return b, 0 })
			err = prepareGuestWithDial(t.Context(), testConfig(), &record{}, fake)
			if err == nil || err.Error() != "invalid topology report ("+shape+")" {
				t.Fatal("production decoder or diagnostic changed")
			}
		})
	}
}
