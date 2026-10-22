package winguest

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDisplayTranscripts(t *testing.T) {
	for _, test := range []struct {
		name, lines string
		ack, pass   bool
	}{
		{"success", "idd_status:not_found", true, true},
		{"wrong", "idd_status:error", true, false},
		{"VDD present", "idd_status:ok", true, false},
		{"unknown", "idd_status:guest-private-output", true, false},
		{"VDD disabled", "idd_status:disabled", true, false},
		{"disabled synthetic", "hyperv_video:disabled\nidd_status:not_found", true, false},
		{"missing key ack", "idd_status:not_found", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			a, err := Initialize(ctx, host, []byte(testKey))
			_ = host.Close()
			if scriptErr := <-done; scriptErr != nil && !errors.Is(scriptErr, io.ErrClosedPipe) {
				t.Fatal(scriptErr)
			}
			if (err == nil) != test.pass || (test.pass && (!a.KeyDeployed || !a.VDDAbsent)) || (err != nil && strings.Contains(err.Error(), "guest-private-output")) {
				t.Fatalf("contract outcome: %+v %v", a, err)
			}
		})
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
		if bad.SyntheticOK() || bad.LabOK() {
			t.Fatal("synthetic topology gate")
		}
	}
	// Windows Security is observational even when both facts are false.
	good.SecurityWindow = true
	good.SecurityOnPrimary = true
	if !good.LabOK() {
		t.Fatal("security observation affected gate")
	}
}
