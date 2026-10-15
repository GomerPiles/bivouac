//go:build windows

package hcsspike

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeBackend struct {
	c                                               Config
	vm                                              *fakeSystem
	createFault                                     string
	prepareErr, startErr, gpuErr, probeErr, openErr error
	probeChange                                     func(*fakeSystem)
	creates, prepares, probes, stops                int
}
type fakeSystem struct {
	api   *fakeBackend
	props properties
}

func (s *fakeSystem) Properties(context.Context) (properties, error) { return s.props, nil }
func (s *fakeSystem) Start(context.Context) error                    { s.props.State = "Running"; return s.api.startErr }
func (s *fakeSystem) GPU(context.Context) error                      { return s.api.gpuErr }
func (s *fakeSystem) Terminate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.api.stops++
	s.api.vm = nil
	return nil
}
func (*fakeSystem) Close() {}
func (f *fakeBackend) Open(_ context.Context, name string) (system, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	if f.vm == nil || f.vm.props.ID != name {
		return nil, errMissing
	}
	return f.vm, nil
}
func (f *fakeBackend) Prepare(_ context.Context, c Config) error {
	f.prepares++
	if err := os.WriteFile(c.disk(), []byte("disposable"), 0o600); err != nil {
		return err
	}
	return f.prepareErr
}
func (f *fakeBackend) Create(_ context.Context, c Config) (system, bool, error) {
	f.creates++
	if f.createFault == "before" {
		return nil, true, errors.New("create dispatch failed")
	}
	if f.createFault == "unknown-absent" {
		return nil, false, errors.New("create timeout")
	}
	f.vm = &fakeSystem{api: f, props: properties{ID: c.name(), Owner: c.owner(), SystemType: "VirtualMachine", RuntimeID: "12345678-1234-4234-8234-123456789abc", State: "Created"}}
	if f.createFault == "after" {
		return f.vm, false, errors.New("create response lost")
	}
	return f.vm, true, nil
}
func (f *fakeBackend) Probe(_ context.Context, _ Config, _ string) (Report, error) {
	f.probes++
	if f.probeChange != nil {
		f.probeChange(f.vm)
	}
	return Report{AgentConnected: true, DisplayReady: true, SSHAuthenticated: f.probeErr == nil}, f.probeErr
}

func testJournal(t *testing.T) (Config, *journal) {
	t.Helper()
	c := exampleConfig()
	c.Root = filepath.Join(t.TempDir(), "HCS-Spike")
	if err := os.Mkdir(c.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	j, err := openJournal(c.Root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := j.root.Close(); err != nil {
			t.Error(err)
		}
	})
	return c, j
}

func TestTrialCleansUpSuccessfulAndPartialMutations(t *testing.T) {
	for _, fault := range []string{"none", "prepare", "create-before", "create-after", "start", "gpu", "probe"} {
		t.Run(fault, func(t *testing.T) {
			c, j := testJournal(t)
			f := &fakeBackend{c: c}
			failure := errors.New("injected failure")
			switch fault {
			case "prepare":
				f.prepareErr = failure
			case "create-before":
				f.createFault = "before"
			case "create-after":
				f.createFault = "after"
			case "start":
				f.startErr = failure
			case "gpu":
				f.gpuErr = failure
			case "probe":
				f.probeErr = failure
			}
			report, err := trial(context.Background(), c, j, f, false)
			if (err != nil) != (fault != "none") {
				t.Fatalf("fault=%s report=%+v err=%v", fault, report, err)
			}
			if !report.Cleaned || f.vm != nil {
				t.Fatal("disposable state retained after confirmed cleanup")
			}
			if _, err := j.root.Stat(recordName(c)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("ownership record retained")
			}
			if _, err := j.root.Stat(c.InstanceID); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("child retained")
			}
			if f.creates > 1 {
				t.Fatal("ambiguous create was replayed")
			}
			if fault == "gpu" && f.probes != 0 {
				t.Fatal("GPU failure admitted guest probe")
			}
		})
	}
}

func TestTrialNeverReplacesExistingNativeGuest(t *testing.T) {
	c, j := testJournal(t)
	f := &fakeBackend{c: c}
	f.vm = &fakeSystem{api: f, props: properties{ID: c.name(), Owner: "foreign"}}
	if _, err := trial(context.Background(), c, j, f, false); err == nil {
		t.Fatal("existing name accepted")
	}
	if f.creates != 0 || f.prepares != 0 || f.stops != 0 {
		t.Fatal("existing native guest modified")
	}
}

func TestUnknownCreateRetainsIntentUntilNativeInstanceIsProved(t *testing.T) {
	c, j := testJournal(t)
	f := &fakeBackend{c: c, createFault: "unknown-absent"}
	report, err := trial(context.Background(), c, j, f, false)
	if err == nil || report.Cleaned || f.creates != 1 {
		t.Fatal("unknown create was released or replayed")
	}
	if _, err = j.root.Stat(filepath.Join(c.InstanceID, "disk.vhdx")); err != nil {
		t.Fatal("pending create lost its disk")
	}
	// A later exact native observation resolves the outstanding intent.
	f.vm = &fakeSystem{api: f, props: properties{ID: c.name(), Owner: c.owner(), SystemType: "VirtualMachine", RuntimeID: "12345678-1234-4234-8234-123456789abc", State: "Running"}}
	if err = cleanup(context.Background(), c, j, f); err != nil {
		t.Fatal(err)
	}
	if f.stops != 1 || f.creates != 1 {
		t.Fatal("recovery did not clean only the original dispatch")
	}
}

func TestCleanupRetainsChangedNativeOwnership(t *testing.T) {
	for _, field := range []string{"owner", "runtime", "type"} {
		t.Run(field, func(t *testing.T) {
			c, j := testJournal(t)
			f := &fakeBackend{c: c, probeChange: func(s *fakeSystem) {
				switch field {
				case "owner":
					s.props.Owner = "foreign"
				case "runtime":
					s.props.RuntimeID = "different-runtime"
				case "type":
					s.props.SystemType = "Container"
				}
			}}
			report, err := trial(context.Background(), c, j, f, false)
			if err == nil || report.Cleaned || f.stops != 0 {
				t.Fatal("changed native identity stopped or cleanup claimed")
			}
			if _, err := j.root.Stat(recordName(c)); err != nil {
				t.Fatal("lost ownership record")
			}
			if _, err := j.root.Stat(c.InstanceID); err != nil {
				t.Fatal("lost retained disk")
			}
		})
	}
}

func seedRecord(t *testing.T, c Config, j *journal, r record, marker bool) {
	t.Helper()
	if err := j.write(recordName(c), r, true); err != nil {
		t.Fatal(err)
	}
	if marker {
		if err := j.root.Mkdir(c.InstanceID, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := j.write(markerName(c), c, true); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCleanupRecoversIntentAndCompletedChildDeletion(t *testing.T) {
	for _, phase := range []string{"intent", "empty-intent", "deleted-child", "empty-deleted-child"} {
		t.Run(phase, func(t *testing.T) {
			c, j := testJournal(t)
			r := record{Config: c, Attempted: strings.Contains(phase, "deleted"), Deleting: strings.Contains(phase, "deleted")}
			seedRecord(t, c, j, r, false)
			if strings.HasPrefix(phase, "empty-") {
				if err := j.root.Mkdir(c.InstanceID, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			f := &fakeBackend{c: c}
			if err := cleanup(context.Background(), c, j, f); err != nil {
				t.Fatal(err)
			}
			if f.stops != 0 {
				t.Fatal("intent recovery stopped a guest")
			}
		})
	}
}

func TestCleanupRefusesMissingOrChangedMarker(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "changed"}[changed], func(t *testing.T) {
			c, j := testJournal(t)
			seedRecord(t, c, j, record{Config: c, Attempted: true}, true)
			if changed {
				other := c
				other.CPU++
				if err := j.write(markerName(c), other, false); err != nil {
					t.Fatal(err)
				}
			} else if err := j.root.Remove(markerName(c)); err != nil {
				t.Fatal(err)
			}
			f := &fakeBackend{c: c}
			if err := cleanup(context.Background(), c, j, f); err == nil {
				t.Fatal("invalid marker accepted")
			}
			if f.stops != 0 {
				t.Fatal("unproved VM stopped")
			}
			if _, err := j.root.Stat(recordName(c)); err != nil {
				t.Fatal("journal lost")
			}
		})
	}
}

func TestCleanupNeverRecursivelyDeletesUnmarkedChild(t *testing.T) {
	c, j := testJournal(t)
	seedRecord(t, c, j, record{Config: c, Attempted: true, Deleting: true}, false)
	if err := j.root.Mkdir(c.InstanceID, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := j.root.WriteFile(filepath.Join(c.InstanceID, "foreign"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(context.Background(), c, j, &fakeBackend{c: c}); err == nil {
		t.Fatal("unmarked child removed")
	}
	if _, err := j.root.Stat(filepath.Join(c.InstanceID, "foreign")); err != nil {
		t.Fatal("foreign data lost")
	}
}

func TestCleanupAfterCancellationUsesIndependentContext(t *testing.T) {
	c, j := testJournal(t)
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeBackend{c: c, probeErr: context.Canceled, probeChange: func(*fakeSystem) { cancel() }}
	report, err := trial(ctx, c, j, f, false)
	if !errors.Is(err, context.Canceled) || !report.Cleaned || f.stops != 1 {
		t.Fatalf("cleanup canceled: %+v %v", report, err)
	}
}

func TestCLIRefusesLiveOperationsWithoutElevation(t *testing.T) {
	info, err := Check()
	if err != nil {
		t.Skip("host does not provide HCS exports")
	}
	if info["administrator"] == true {
		t.Skip("requires an ordinary token")
	}
	for _, mode := range []string{"trial", "cleanup"} {
		err := RunCLI(context.Background(), []string{mode, "--config", filepath.Join(t.TempDir(), "missing.json")}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "no elevation was requested") {
			t.Fatalf("did not refuse before config access: %v", err)
		}
	}
}

func TestBootOnlyNeverInitializesGuest(t *testing.T) {
	c, j := testJournal(t)
	f := &fakeBackend{c: c}
	report, err := trial(context.Background(), c, j, f, true)
	if err != nil || !report.NativeStarted || !report.GPUAssigned || !report.Cleaned {
		t.Fatalf("native trial: %+v %v", report, err)
	}
	if f.probes != 0 || report.AgentConnected || report.DisplayReady || report.SSHAuthenticated {
		t.Fatal("native-only test admitted or claimed guest initialization")
	}
}
