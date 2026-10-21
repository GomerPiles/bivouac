package winguest

import (
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDisplayModes(t *testing.T) {
	for _, value := range []string{"", "vdd", "synthetic", "VDD", "guest-private-output"} {
		fs := flag.NewFlagSet("display", flag.ContinueOnError)
		v := fs.String("lab.display", "vdd", "")
		if err := fs.Parse([]string{"-lab.display=" + value}); err != nil {
			t.Fatal(err)
		}
		mode, err := ParseDisplayMode(*v)
		valid := value == "" || value == "vdd" || value == "synthetic"
		if (err == nil) != valid || (err != nil && strings.Contains(err.Error(), "guest-private-output")) {
			t.Fatal("display parsing")
		}
		if value == "" && mode != DisplayVDD {
			t.Fatal("default")
		}
	}
}

func TestDisplayTranscripts(t *testing.T) {
	for _, mode := range []DisplayMode{DisplayVDD, DisplaySynthetic} {
		status := "idd_status:ok"
		if mode == DisplaySynthetic {
			status = "idd_status:not_found"
		}
		for _, test := range []struct {
			name, lines string
			ack, pass   bool
		}{
			{"success", status, true, true},
			{"wrong", "idd_status:error", true, false},
			{"wrong mode", map[DisplayMode]string{DisplayVDD: "idd_status:not_found", DisplaySynthetic: "idd_status:ok"}[mode], true, false},
			{"disabled synthetic", "hyperv_video:disabled\n" + status, true, mode == DisplayVDD},
			{"missing key ack", status, false, false},
		} {
			t.Run(string(mode)+"/"+test.name, func(t *testing.T) {
				host, guest := net.Pipe()
				defer func() { _ = host.Close() }()
				done := make(chan error, 1)
				go func() {
					defer func() { _ = guest.Close() }()
					r, err := readInitialization(guest)
					if err == nil {
						_, err = io.WriteString(guest, "ssh_ready\n")
					}
					if err == nil {
						var key string
						key, err = r.ReadString('\n')
						if err == nil && key != "ssh_deploy_key "+testKey+"\n" {
							err = errors.New("key frame")
						}
					}
					if err == nil {
						text := test.lines + "\n"
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
				a, err := Initialize(ctx, host, []byte(testKey), mode)
				_ = host.Close()
				if scriptErr := <-done; scriptErr != nil && !errors.Is(scriptErr, io.ErrClosedPipe) {
					t.Fatal(scriptErr)
				}
				if (err == nil) != test.pass || (test.pass && (!a.KeyDeployed || !a.DisplayReady)) {
					t.Fatalf("contract outcome: %+v %v", a, err)
				}
			})
		}
	}
}

func TestTopologyGates(t *testing.T) {
	good := Topology{TopologyValid: true, ActiveDisplays: 1, PrimaryDisplays: 1, PrimaryWidth: 1024, PrimaryHeight: 768, VirtualEqualsPrimary: true, AdapterKind: 1, HyperVEnabled: true, HyperVStarted: true, ProbeForeground: true, ProbeOnPrimary: true, ProbeInput: true}
	if !good.LabOK() || !good.SyntheticOK() {
		t.Fatal("valid topology refused")
	}
	for name, change := range map[string]func(*Topology){
		"missing": func(v *Topology) { v.TopologyValid = false }, "multiple": func(v *Topology) { v.ActiveDisplays = 3 }, "no primary": func(v *Topology) { v.PrimaryDisplays = 0 }, "two primary": func(v *Topology) { v.PrimaryDisplays = 2 }, "virtual": func(v *Topology) { v.VirtualEqualsPrimary = false }, "width": func(v *Topology) { v.PrimaryWidth = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := good
			change(&bad)
			if bad.LabOK() || bad.SyntheticOK() {
				t.Fatal("invalid topology accepted")
			}
		})
	}
	for _, change := range []func(*Topology){func(v *Topology) { v.ProbeForeground = false }, func(v *Topology) { v.ProbeOnPrimary = false }, func(v *Topology) { v.ProbeInput = false }} {
		bad := good
		change(&bad)
		if bad.LabOK() || !bad.SyntheticOK() {
			t.Fatal("lab-only gate")
		}
	}
	for _, change := range []func(*Topology){func(v *Topology) { v.VDDNodes = 1 }, func(v *Topology) { v.AdapterKind = 2 }, func(v *Topology) { v.HyperVEnabled = false }, func(v *Topology) { v.HyperVStarted = false }} {
		bad := good
		change(&bad)
		if bad.SyntheticOK() || !bad.LabOK() {
			t.Fatal("synthetic-only gate")
		}
	}
	// Windows Security is observational even when both facts are false.
	good.SecurityWindow = true
	good.SecurityOnPrimary = true
	if !good.LabOK() {
		t.Fatal("security observation affected gate")
	}
}
