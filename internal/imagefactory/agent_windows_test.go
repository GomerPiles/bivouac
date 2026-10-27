//go:build windows

package imagefactory

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/guestagent"
)

func factoryFrame(r io.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > 65536 {
		return 0, nil, errors.New("fixture frame bound")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return h[0], b, err
}
func sendFactoryFrame(w io.Writer, kind byte, b []byte) error {
	h := []byte{kind}
	h = binary.BigEndian.AppendUint32(h, uint32(len(b))) // #nosec G115 -- bounded fixture bytes.
	if _, err := w.Write(h); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// Speak the real framed protocol without executing any guest commands.
func fakeFactoryAgent(respond func([]string, []byte) ([]byte, int)) guestagent.Dialer {
	return fakeFactoryAgentFrames(respond, 32768, 0)
}

func fakeFactoryAgentFrames(respond func([]string, []byte) ([]byte, int), frameSize, writeSize int) guestagent.Dialer {
	return func(context.Context) (net.Conn, error) {
		host, guest := net.Pipe()
		go func() {
			defer func() { _ = guest.Close() }()
			kind, p, err := factoryFrame(guest)
			if err != nil || kind != 'R' {
				return
			}
			var request struct {
				V     int
				Argv  []string
				Stdin bool
			}
			if json.Unmarshal(p, &request) != nil || request.V != guestagent.Version {
				return
			}
			var input []byte
			if request.Stdin {
				for {
					kind, p, err = factoryFrame(guest)
					if err != nil || kind != 'I' {
						return
					}
					if len(p) == 0 {
						break
					}
					input = append(input, p...)
					if len(input) > 65536 {
						return
					}
				}
			}
			output, code := respond(request.Argv, input)
			var wire bytes.Buffer
			for len(output) > 0 {
				n := min(len(output), frameSize)
				if sendFactoryFrame(&wire, 'O', output[:n]) != nil {
					return
				}
				output = output[n:]
			}
			if sendFactoryFrame(&wire, 'E', []byte("guest-private-output")) != nil {
				return
			}
			status := binary.BigEndian.AppendUint32(nil, uint32(code)) // #nosec G115 -- small fixture exit codes.
			if sendFactoryFrame(&wire, 'X', status) != nil {
				return
			}
			if writeSize <= 0 {
				_, _ = guest.Write(wire.Bytes())
				return
			}
			for wire.Len() > 0 {
				if _, err := guest.Write(wire.Next(min(writeSize, wire.Len()))); err != nil {
					return
				}
			}
		}()
		return host, nil
	}
}

// answerInstallation lets a preparation fake pass the installation self-test
// with valid facts and hands every other command to respond.
func answerInstallation(respond func([]string, []byte) ([]byte, int)) func([]string, []byte) ([]byte, int) {
	return func(argv []string, input []byte) ([]byte, int) {
		if slices.Equal(argv, []string{guestagent.WindowsPath, "guest-agent", "selftest", "inspect"}) {
			task := guestagent.TaskFacts{TaskUser: true, TaskHighest: true, TaskInteractive: true, TaskAction: true, TaskPriority: 4, TaskPolicy: true, TaskSecurity: true}
			b, _ := json.Marshal(guestagent.InstallationFacts{AutologonAccountMatches: true, TaskUser: true, TaskHighest: true, TaskInteractive: true, TaskAction: true, TaskPriority: 4, OwnerTrusted: true, ACLProtected: true, ACLExpected: true, RunnerTask: task})
			return b, 0
		}
		return respond(argv, input)
	}
}

func TestFactoryAgentConversation(t *testing.T) {
	var stages []string
	r := &record{Name: "bivouac-aaaaaaa", Manifest: Manifest{ProbeSHA256: strings.Repeat("a", 64), ValidationSHA256: strings.Repeat("b", 64), AutologonSHA256: strings.Repeat("c", 64)}}
	dial := fakeFactoryAgent(func(argv []string, input []byte) ([]byte, int) {
		if slices.Equal(argv, []string{guestagent.WindowsPath, "version"}) {
			stages = append(stages, "proof")
			return []byte("version"), 0
		}
		if slices.Equal(argv, []string{guestagent.WindowsPath, "guest-agent", "selftest", "inspect"}) {
			stages = append(stages, "installation")
			f := guestagent.InstallationFacts{AutologonAccountMatches: true, TaskUser: true, TaskHighest: true, TaskInteractive: true, TaskAction: true, TaskPriority: 4, OwnerTrusted: true, ACLProtected: true, ACLExpected: true, RunnerTask: guestagent.TaskFacts{TaskUser: true, TaskHighest: true, TaskInteractive: true, TaskAction: true, TaskPriority: 4, TaskPolicy: true, TaskSecurity: true}}
			b, _ := json.Marshal(f)
			return b, 0
		}
		want := []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedPowerShell(guestBootstrap)}
		if !slices.Equal(argv, want) || len(input) < 4 || int(binary.LittleEndian.Uint32(input)) != len(input)-4 {
			return nil, 18
		}
		var payload struct {
			Script string
			Data   map[string]any
		}
		if json.Unmarshal(input[4:], &payload) != nil {
			return nil, 18
		}
		switch {
		case payload.Script == validateEntry:
			stages = append(stages, "validate")
			if payload.Data["require_setup"] != true || payload.Data["script_sha256"] != r.Manifest.ValidationSHA256 {
				return nil, 14
			}
			return []byte(`{"secure_boot":true,"tpm_present":true,"tpm_ready":true,"guest_ready":true,"desktop_ready":true,"hardware_d3d11":true,"presented":true,"pixel_readback":true,"stage":7,"hresult":0,"vendor_id":4098,"device_id":1,"adapter_count":2,"hardware_adapter_count":1,"gpu_device_diagnostics_valid":true,"display_device_count":2,"virtual_render_device_count":1,"virtual_render_problem_code":0,"topology_valid":true,"active_display_count":1,"primary_display_count":1,"primary_width":1024,"primary_height":768,"virtual_equals_primary":true,"primary_adapter_kind":1,"vdd_node_count":0,"hyperv_video_enabled":true,"hyperv_video_started":true}`), 0
		case payload.Script == sanitizeEntry:
			stages = append(stages, "sanitize")
			return []byte("sanitized-shutdown-scheduled"), 0
		case strings.Contains(payload.Script, "hcs-runner-check.ps1"):
			stages = append(stages, "runner")
			return []byte("2.300.0"), 0
		default:
			return nil, 18
		}
	})
	if err := prepareGuestWithDial(t.Context(), testConfig(), r, dial); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stages, []string{"proof", "installation", "validate", "runner", "installation", "sanitize"}) || r.Manifest.Topology == nil || r.Manifest.RunnerVersion != "2.300.0" || !r.Manifest.AutologonAccountMatches {
		t.Fatal("wrong factory conversation")
	}
}

func TestFactoryInstallationRequiresAutologonAgreement(t *testing.T) {
	goodTask := guestagent.TaskFacts{TaskUser: true, TaskHighest: true, TaskInteractive: true, TaskAction: true, TaskPriority: 4, TaskPolicy: true, TaskSecurity: true}
	for _, mode := range []string{"matching", "mismatch", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f := guestagent.InstallationFacts{TaskUser: true, TaskHighest: true, TaskInteractive: true, TaskAction: true, TaskPriority: 4, OwnerTrusted: true, ACLProtected: true, ACLExpected: true, RunnerTask: goodTask, AutologonAccountMatches: mode == "matching"}
			raw, _ := json.Marshal(f)
			if mode == "missing" {
				var fields map[string]any
				_ = json.Unmarshal(raw, &fields)
				delete(fields, "autologon_account_matches")
				raw, _ = json.Marshal(fields)
			}
			dial := fakeFactoryAgent(func(argv []string, input []byte) ([]byte, int) {
				if !slices.Equal(argv, []string{guestagent.WindowsPath, "guest-agent", "selftest", "inspect"}) || len(input) != 0 {
					t.Error("unexpected inspection command")
					return nil, 1
				}
				return raw, 0
			})
			var manifest Manifest
			err := inspectInstallation(t.Context(), dial, &manifest)
			if (err == nil) != (mode == "matching") || manifest.AutologonAccountMatches != (mode == "matching") {
				t.Fatal("installation/manifest accepted missing equality proof")
			}
			if err != nil && !strings.Contains(err.Error(), `"autologon_account_matches":false`) {
				t.Fatal("refusal does not name the failing installation fact")
			}
		})
	}
}

func TestFactoryAgentFailureBounds(t *testing.T) {
	for _, mode := range []string{"step", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			dial := fakeFactoryAgent(func([]string, []byte) ([]byte, int) {
				if mode == "step" {
					return []byte("guest-private-output"), 37
				}
				return []byte(strings.Repeat("x", 8193)), 0
			})
			out, err := guestRun(t.Context(), dial, validateEntry, map[string]string{})
			if err == nil || out != nil || strings.Contains(err.Error(), "guest-private-output") {
				t.Fatal("unbounded guest output or error disclosure")
			}
			if mode == "step" && !strings.Contains(err.Error(), "step 37") {
				t.Fatal("step mapping lost")
			}
		})
	}
}
