//go:build windows && integration

package appsandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/winhost"
	"golang.org/x/sys/windows"
)

func TestWindowsNativeFailureRecovery(t *testing.T) {
	configPath := os.Getenv("BIVOUAC_WINDOWS_NATIVE_TEST_CONFIG")
	if configPath == "" {
		t.Skip("operator-provided isolated native configuration required")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("explicit operator elevation required")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var opts BrokerOptions
	if json.Unmarshal(data, &opts) != nil || opts.ControllerID != "windows-native-failure-validation" || filepath.Base(opts.Root) != "FailureInstances" || opts.MaxInstances != 1 {
		t.Fatal("separate native failure root/binding required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	engine, closeEngine, err := OpenNativeEngine(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeEngine() })
	if records, e := engine.records.All(); e != nil || len(records) != 0 {
		t.Fatal("native failure root is not empty; retain and inspect")
	}
	owned, foreign, err := engine.List(ctx)
	if err != nil || len(owned) != 0 {
		t.Fatal("native inventory unavailable")
	}
	for _, vm := range foreign {
		if vm.Running || vm.Prefixed {
			t.Fatal("foreign native VM active or prefixed; test refused")
		}
	}
	newClone := func(t *testing.T) CloneRecord {
		t.Helper()
		var id [4]byte
		if _, e := rand.Read(id[:]); e != nil {
			t.Fatal(e)
		}
		instanceID := hex.EncodeToString(id[:])
		r, e := PlanClone(opts.Root, provider.Spec{Name: "bivouac-failure-" + instanceID, Baseline: opts.Baseline, CPU: opts.MaxCPU, MemoryMB: opts.MaxMemoryMB, Meta: provider.Metadata{ControllerID: opts.ControllerID, InstanceID: instanceID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}, opts.MaxDiskGB, 0)
		if e != nil {
			t.Fatal(e)
		}
		// Keep exact ownership on failures; cleanup never erases an ambiguous
		// record or recursively removes native storage.
		t.Cleanup(func() {
			cleanupCtx, c := context.WithTimeout(context.Background(), time.Minute)
			defer c()
			if e := engine.Delete(cleanupCtx, r.RunnerName); e != nil && !errors.Is(e, provider.ErrNotFound) {
				t.Errorf("retained native cleanup: %v", e)
			}
		})
		return r
	}
	reopen := func(t *testing.T) {
		t.Helper()
		closeEngine()
		next, closeNext, openErr := OpenNativeEngine(ctx, opts)
		if openErr != nil {
			t.Fatal(openErr)
		}
		engine, closeEngine = next, closeNext
	}
	preflight := func(t *testing.T, r CloneRecord) {
		t.Helper()
		ssh, scp, e := winhost.OpenSSH()
		if e != nil {
			t.Fatal(e)
		}
		key, e := DefaultSSHKey()
		if e != nil {
			t.Fatal(e)
		}
		guest, e := NewSSHGuest(GuestOptions{StateDir: t.TempDir(), SSHBinary: ssh, SCPBinary: scp, SSHKey: key, Helper: os.Getenv("BIVOUAC_WINDOWS_NATIVE_TEST_HELPER"), RunnerDir: `C:\actions-runner`}, nil)
		if e != nil {
			t.Fatal(e)
		}
		deadline := time.Now().Add(8 * time.Minute)
		for time.Now().Before(deadline) {
			lease, e := engine.Lookup(ctx, r.RunnerName)
			if e != nil {
				t.Fatal(e)
			}
			if lease.VM.Running && lease.VM.AgentOnline && lease.VM.InstallComplete && lease.SSH.ForwardReady() {
				if e = guest.Preflight(ctx, lease); e != nil {
					t.Fatal(e)
				}
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(500 * time.Millisecond):
			}
		}
		t.Fatal("native fixture did not reach console preflight")
	}

	if !t.Run("lost-create-and-delete-responses", func(t *testing.T) {
		r := newClone(t)
		base := engine.api
		engine.api = &nativeAPIFault{NativeAPI: base, createAfter: true}
		if e := engine.Create(ctx, r); !errors.Is(e, ErrOutcomeUnknown) {
			t.Fatalf("create outcome: %v", e)
		}
		record, e := engine.records.Get(r.RunnerName)
		if e != nil || record.Phase != "creating" || !record.Attempted {
			t.Fatal("ambiguous create lost dispatch intent")
		}
		if _, e = engine.records.Child(r); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("child marker committed before create response")
		}
		reopen(t)
		if _, e = engine.Lookup(ctx, r.RunnerName); e != nil {
			t.Fatal(e)
		}
		if marker, e := engine.records.Child(r); e != nil || marker != r {
			t.Fatal("protected native identity did not recover marker")
		}
		if e = engine.Create(ctx, r); e == nil {
			t.Fatal("blind create retry accepted")
		}
		engine.api = &nativeAPIFault{NativeAPI: engine.api, deleteAfter: true}
		if e = engine.Delete(ctx, r.RunnerName); !errors.Is(e, ErrOutcomeUnknown) {
			t.Fatalf("delete outcome: %v", e)
		}
		if _, e = engine.records.Get(r.RunnerName); e != nil {
			t.Fatal("ambiguous delete lost reservation")
		}
		reopen(t)
		if e = engine.Delete(ctx, r.RunnerName); e != nil {
			t.Fatal(e)
		}
	}) {
		return
	}
	if !t.Run("partial-network-and-cleanup-restart", func(t *testing.T) {
		r := newClone(t)
		if e := engine.Create(ctx, r); e != nil {
			t.Fatal(e)
		}
		preflight(t, r)
		fault := &nativeNetworkFault{NativeNetwork: engine.net, attachAfter: true, deleteBefore: true}
		engine.net = fault
		if _, e := engine.Prepare(ctx, r.RunnerName); e == nil {
			t.Fatal("interrupted network setup admitted guest")
		}
		record, e := engine.records.Get(r.RunnerName)
		if e != nil || record.Phase != "networking" || record.Network == nil {
			t.Fatal("partial networking lost intent")
		}
		if e = engine.Verify(ctx, r.RunnerName); e == nil {
			t.Fatal("partial setup verified ready")
		}
		if e = engine.Guard(ctx); e == nil {
			t.Fatal("partial setup did not quarantine")
		}
		if e = engine.Delete(ctx, r.RunnerName); e == nil {
			t.Fatal("cleanup failure lost reservation")
		}
		record, e = engine.records.Get(r.RunnerName)
		if e != nil || record.Phase != "native_deleted" || record.Network == nil {
			t.Fatal("network cleanup reservation missing")
		}
		reopen(t)
		if e = engine.Delete(ctx, r.RunnerName); e != nil {
			t.Fatal(e)
		}
	}) {
		return
	}
	if !t.Run("ownership-refusal-and-failed-block-stops-guest", func(t *testing.T) {
		r := newClone(t)
		if e := engine.Create(ctx, r); e != nil {
			t.Fatal(e)
		}
		preflight(t, r)
		if _, e := engine.Prepare(ctx, r.RunnerName); e != nil {
			t.Fatal(e)
		}
		changed := r
		changed.Meta.ControllerID = "foreign-controller"
		if e := engine.records.MarkChild(changed); e != nil {
			t.Fatal(e)
		}
		// Restore the test marker on assertion failure before scoped cleanup.
		markerAltered := true
		defer func() {
			if markerAltered {
				if e := engine.records.MarkChild(r); e != nil {
					t.Errorf("restore test marker: %v", e)
				}
			}
		}()
		if e := engine.Delete(ctx, r.RunnerName); !errors.Is(e, provider.ErrNotOwned) {
			t.Fatalf("ownership refusal: %v", e)
		}
		if e := engine.records.MarkChild(r); e != nil {
			t.Fatal(e)
		}
		markerAltered = false
		lease, e := engine.Lookup(ctx, r.RunnerName)
		if e != nil || !lease.VM.Running {
			t.Fatal("ownership refusal mutated native VM")
		}
		engine.net = &nativeNetworkFault{NativeNetwork: engine.net, verifyBefore: true, blockBefore: true}
		if e = engine.Guard(ctx); e == nil {
			t.Fatal("failed block not reported")
		}
		lease, e = engine.Lookup(ctx, r.RunnerName)
		if e != nil || lease.VM.Running {
			t.Fatal("failed block did not stop exact owned VM")
		}
		record, e := engine.records.Get(r.RunnerName)
		if e != nil || record.Phase != "quarantined" {
			t.Fatal("quarantine not durable")
		}
		if e = engine.Start(ctx, r.RunnerName); e == nil {
			t.Fatal("stopped network binding restarted")
		}
		reopen(t)
		if e = engine.Delete(ctx, r.RunnerName); e != nil {
			t.Fatal(e)
		}
	}) {
		return
	}
	if records, e := engine.records.All(); e != nil || len(records) != 0 {
		t.Fatal("native reservations remain")
	}
	owned, _, err = engine.List(ctx)
	if err != nil || len(owned) != 0 {
		t.Fatal("owned native VM remains")
	}
}
