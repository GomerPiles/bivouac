//go:build windows

package vmhost

import (
	"context"
	"errors"
	"testing"

	"github.com/GomerPiles/bivouac/internal/sandboxdiscovery"
)

func TestSandboxOnlyConfigurationNeedsNoImagesOrHCSLifecycle(t *testing.T) {
	cfg := Config{Root: `C:\Bivouac\Host`, SandboxAccounts: []string{alice}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.HCSEnabled() {
		t.Fatal("Sandbox discovery enabled HCS lifecycle")
	}
	for _, change := range []func(*Config){func(c *Config) { c.Controller = "other" }, func(c *Config) { c.Images = map[string]string{"image": `C:\Images\base.vhdx`} }, func(c *Config) { c.MaxInstances = 1 }, func(c *Config) { c.MaxCPU = 2 }, func(c *Config) { c.MaxMemoryMB = 4096 }} {
		bad := cfg
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("inactive HCS settings accepted")
		}
	}
	server := NewServer(nil, cfg)
	queries := 0
	server.discoverSandbox = func(context.Context) ([]sandboxdiscovery.Candidate, error) {
		queries++
		return []sandboxdiscovery.Candidate{}, nil
	}
	for _, request := range []Request{createReq("bivouac-forbidden"), {Op: "list"}, {Op: "info"}, {Op: "destroy", Name: "bivouac-forbidden"}, {Op: "status", Name: "bivouac-forbidden"}} {
		if response := call(t, server, alice, request); response.Code != CodeRefused {
			t.Fatal("Sandbox account reached HCS lifecycle")
		}
	}
	if response := call(t, server, alice, Request{Op: "sandbox-candidates"}); response.Code != "" || queries != 1 {
		t.Fatal("authorized Sandbox discovery failed")
	}
	if response := call(t, server, bob, Request{Op: "sandbox-candidates"}); response.Code != CodeRefused || queries != 1 {
		t.Fatal("foreign SID reached discovery")
	}
}

func TestDiscoveryCapabilityIsSeparateAndCannotAdoptOrDestroyGuests(t *testing.T) {
	server, native := serverFixture(t)
	server.cfg.SandboxAccounts = []string{eve}
	queries := 0
	server.discoverSandbox = func(context.Context) ([]sandboxdiscovery.Candidate, error) {
		queries++
		return []sandboxdiscovery.Candidate{{ID: "11111111-2222-4333-8444-555555555555", RuntimeID: "66666666-7777-4888-8999-aaaaaaaaaaaa"}}, nil
	}
	if call(t, server, alice, createReq("bivouac-owned")).Code != "" {
		t.Fatal("existing HCS create failed")
	}
	if response := call(t, server, alice, Request{Op: "sandbox-candidates"}); response.Code != CodeRefused {
		t.Fatal("HCS SID implicitly gained Sandbox capability")
	}
	for _, request := range []Request{{Op: "destroy", Name: "bivouac-owned"}, {Op: "list"}, createReq("bivouac-forbidden"), {Op: "sandbox-candidates", Name: "bivouac-owned"}, {Op: "sandbox-candidates", Create: createReq("bivouac-forbidden").Create}} {
		if call(t, server, eve, request).Code != CodeRefused {
			t.Fatal("discovery actor received lifecycle authority")
		}
	}
	if response := call(t, server, eve, Request{Op: "sandbox-candidates"}); response.Code != "" || len(response.SandboxCandidates) != 1 || queries != 1 {
		t.Fatal("Sandbox discovery failed")
	}
	if len(native.systems) != 1 || len(server.guests) != 1 {
		t.Fatal("discovery changed HCS ownership")
	}
	if response := call(t, server, alice, Request{Op: "status", Name: "bivouac-owned"}); response.Code != "" || response.Guest == nil {
		t.Fatal("discovery interrupted HCS guest")
	}
	server.discoverSandbox = func(context.Context) ([]sandboxdiscovery.Candidate, error) {
		return nil, errors.New("private native failure details")
	}
	if response := call(t, server, eve, Request{Op: "sandbox-candidates"}); response.Code != CodeFailed || response.Error != "Sandbox native discovery unavailable" {
		t.Fatal("discovery error leaked native details")
	}
}
