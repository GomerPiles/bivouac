package crosvm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/provider"
)

// fakeProcesses maps each PID to its current occupant, if any.
type fakeProcesses struct {
	mu   sync.Mutex
	live map[uint32]ProcessIdentity
}

func (f *fakeProcesses) alive(expected ProcessIdentity) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	actual, ok := f.live[expected.PID]
	if !ok {
		return false, nil
	}
	return compareIdentity(expected, actual)
}

func recordedBackend(t *testing.T, alive func(ProcessIdentity) (bool, error)) (*NativeBackend, Record) {
	t.Helper()
	o, _ := fixture(t)
	b, err := openBackend(o, alive)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	r := recordFor(t, b.Options(), "1234abcd")
	if err := createInstanceDirectory(b.Options().Root, Envelope{Options: b.Options(), Record: r}); err != nil {
		t.Fatal(err)
	}
	return b, r
}

func holdInstanceLock(t *testing.T, r Record) *control.Lock {
	t.Helper()
	lock, err := (control.Files{Dir: r.Directory}).Acquire()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Release() })
	return lock
}

func TestReusedPIDProvesRecordedProcessGone(t *testing.T) {
	recorded := ProcessIdentity{PID: 40, Created: 7, Image: `C:\Tools\crosvm.exe`}
	for _, c := range []struct {
		actual ProcessIdentity
		live   bool
		fails  bool
	}{
		{ProcessIdentity{PID: 40, Created: 7, Image: `c:\tools\CROSVM.EXE`}, true, false},
		{ProcessIdentity{PID: 40, Created: 8, Image: `C:\Tools\crosvm.exe`}, false, false},
		{ProcessIdentity{PID: 40, Created: 9, Image: `C:\Windows\System32\svchost.exe`}, false, false},
		{ProcessIdentity{PID: 40, Created: 7, Image: `C:\Windows\System32\svchost.exe`}, false, true},
	} {
		live, err := compareIdentity(recorded, c.actual)
		if live != c.live || (err != nil) != c.fails {
			t.Fatalf("identity %+v: live=%v err=%v", c.actual, live, err)
		}
	}

	processes := &fakeProcesses{live: map[uint32]ProcessIdentity{}}
	b, r := recordedBackend(t, processes.alive)
	supervisor := ProcessIdentity{PID: 40, Created: 7, Image: `C:\Tools\bivouac.exe`}
	vm := ProcessIdentity{PID: 41, Created: 7, Image: r.Binary}
	if err := writeJSON(r.Directory, "native.json", NativeState{Supervisor: supervisor, VM: vm, Phase: "exited", Empty: true, JobOwned: true}); err != nil {
		t.Fatal(err)
	}
	// After a reboot both PIDs belong to unrelated processes.
	processes.live[40] = ProcessIdentity{PID: 40, Created: 99, Image: `C:\Windows\System32\svchost.exe`}
	processes.live[41] = ProcessIdentity{PID: 41, Created: 98, Image: r.Binary}
	if _, status, err := b.Lookup(context.Background(), r.Name); err != nil || status.Running || !status.Owned {
		t.Fatal("reused PID blocked lookup", status, err)
	}
	owned, foreign, err := b.List(context.Background())
	if err != nil || len(owned) != 1 || len(foreign) != 0 {
		t.Fatal("reused PID blocked inventory", owned, foreign, err)
	}
	if err := b.Delete(context.Background(), r.Name); err != nil {
		t.Fatal("reused PID blocked cleanup", err)
	}
	if _, err := os.Stat(r.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("instance directory remains")
	}
}

func TestContradictoryIdentityIsQuarantinedNotFatal(t *testing.T) {
	processes := &fakeProcesses{live: map[uint32]ProcessIdentity{}}
	b, r := recordedBackend(t, processes.alive)
	supervisor := ProcessIdentity{PID: 40, Created: 7, Image: `C:\Tools\bivouac.exe`}
	if err := writeJSON(r.Directory, "native.json", NativeState{Supervisor: supervisor, Phase: "exited", Empty: true}); err != nil {
		t.Fatal(err)
	}
	processes.live[40] = ProcessIdentity{PID: 40, Created: 7, Image: `C:\Other\program.exe`}
	if _, _, err := b.Lookup(context.Background(), r.Name); err == nil {
		t.Fatal("contradictory identity accepted")
	}
	owned, foreign, err := b.List(context.Background())
	if err != nil || len(owned) != 0 || len(foreign) != 1 || foreign[0].Name != r.Name || !foreign[0].Prefixed {
		t.Fatal("contradictory entry was not quarantined", owned, foreign, err)
	}
	if err := b.Delete(context.Background(), r.Name); err == nil {
		t.Fatal("contradictory identity deleted")
	}
	if _, err := loadEnvelope(filepath.Join(r.Directory, "owner.json")); err != nil {
		t.Fatal("quarantined instance lost ownership", err)
	}
}

func TestListQuarantinesUnverifiableEntries(t *testing.T) {
	b, r := recordedBackend(t, (&fakeProcesses{}).alive)
	root := b.Options().Root
	for _, dir := range []string{"00000001", "00000002", stagingPrefix + "00000003", "operator-notes"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "00000002", "owner.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, stagingPrefix+"00000003", "disk.qcow2"), []byte("retain"), 0o600); err != nil {
		t.Fatal(err)
	}
	owned, foreign, err := b.List(context.Background())
	if err != nil || len(owned) != 1 || owned[0].Name != r.Name || len(foreign) != 4 {
		t.Fatal("unverifiable entries broke inventory", owned, foreign, err)
	}
	for _, f := range foreign {
		if !f.Prefixed || !f.Running {
			t.Fatal("quarantined entry not reported conservatively", f)
		}
	}
	// An unmarked directory is absent to lifecycle calls but never deleted.
	unmarked := "bivouac-linux-00000001"
	if _, _, err := b.Lookup(context.Background(), unmarked); !errors.Is(err, provider.ErrNotFound) {
		t.Fatal(err)
	}
	if err := b.Delete(context.Background(), unmarked); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "00000001")); err != nil {
		t.Fatal("unmarked directory was deleted")
	}
	if count, err := b.directories(); err != nil || count != 5 {
		t.Fatal("quarantined directories released their reservation", count, err)
	}
}

func TestAbandonedLaunchIsRecoveredUnderTheInstanceLock(t *testing.T) {
	b, r := recordedBackend(t, (&fakeProcesses{}).alive)
	if err := writeJSON(r.Directory, "launch.intent", true); err != nil {
		t.Fatal(err)
	}
	// A dispatched supervisor that has not journalled holds the lock.
	lock := holdInstanceLock(t, r)
	if err := b.Delete(context.Background(), r.Name); err == nil {
		t.Fatal("pending launch deleted")
	}
	if _, err := os.Stat(filepath.Join(r.Directory, "stop")); err != nil {
		t.Fatal("pending supervisor was not told to stop")
	}
	if _, err := os.Stat(filepath.Join(r.Directory, "native.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("native state written without the lock")
	}
	// The supervisor died, or never started, before journalling.
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if err := b.Stop(context.Background(), r.Name, 0); err != nil {
		t.Fatal(err)
	}
	var state NativeState
	if err := readJSON(filepath.Join(r.Directory, "native.json"), &state); err != nil || state.Phase != "failed" || !state.Empty {
		t.Fatal("abandoned launch was not made single-use", state, err)
	}
	if err := b.Delete(context.Background(), r.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("instance directory remains")
	}
}

// A supervisor that was dispatched but has not yet taken the instance lock
// keeps the launch pending while its dispatch identity is alive.
func TestDispatchedSupervisorKeepsLaunchPending(t *testing.T) {
	processes := &fakeProcesses{live: map[uint32]ProcessIdentity{}}
	b, r := recordedBackend(t, processes.alive)
	if err := writeJSON(r.Directory, "launch.intent", true); err != nil {
		t.Fatal(err)
	}
	dispatched := ProcessIdentity{PID: 50, Created: 7, Image: `C:\Tools\bivouac.exe`}
	if err := writeJSON(r.Directory, "dispatch.json", dispatched); err != nil {
		t.Fatal(err)
	}
	processes.live[50] = dispatched
	if err := b.Stop(context.Background(), r.Name, 0); err == nil {
		t.Fatal("launch abandoned while its dispatched supervisor is alive")
	}
	if _, err := os.Stat(filepath.Join(r.Directory, "stop")); err != nil {
		t.Fatal("dispatched supervisor was not told to stop")
	}
	if _, err := os.Stat(filepath.Join(r.Directory, "native.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("native state written while the dispatched supervisor is alive")
	}
	// It saw the stop marker and exited without journalling.
	processes.mu.Lock()
	delete(processes.live, 50)
	processes.mu.Unlock()
	if err := b.Stop(context.Background(), r.Name, 0); err != nil {
		t.Fatal(err)
	}
	var state NativeState
	if err := readJSON(filepath.Join(r.Directory, "native.json"), &state); err != nil || state.Phase != "failed" || !state.Empty {
		t.Fatal("abandoned launch was not made single-use", state, err)
	}
	if err := b.Delete(context.Background(), r.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("instance directory remains")
	}
}

func TestInterruptedJSONWritesDoNotBlockDeletion(t *testing.T) {
	b, r := recordedBackend(t, (&fakeProcesses{}).alive)
	if err := writeJSON(r.Directory, "native.json", NativeState{Phase: "failed", Empty: true}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"owner.json", ".bivouac-owner.json", "native.json", "launch.intent", "dispatch.json"} {
		if err := os.WriteFile(filepath.Join(r.Directory, name+".new"), []byte("{partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Delete(context.Background(), r.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("instance directory remains")
	}
}

func TestInstanceDirectoryAppearsOnlyWithMarkers(t *testing.T) {
	b, r := recordedBackend(t, (&fakeProcesses{}).alive)
	o := b.Options()
	if e, err := loadEnvelope(filepath.Join(r.Directory, "owner.json")); err != nil || e.Options != o || !Equal(e.Record, r) {
		t.Fatal("published envelope differs", err)
	}
	if err := createInstanceDirectory(o.Root, Envelope{Options: o, Record: r}); err == nil {
		t.Fatal("existing instance directory replaced")
	}
	// Simulate Creates that crashed before their rename.
	partial := filepath.Join(o.Root, stagingPrefix+"00000004")
	retained := filepath.Join(o.Root, stagingPrefix+"00000005")
	for _, dir := range []string{partial, retained} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "owner.json.new"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(retained, "unexpected"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b.Close()
	reopened, err := openBackend(o, (&fakeProcesses{}).alive)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := os.Stat(partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("marker-only staging directory was not swept")
	}
	if _, err := os.Stat(filepath.Join(retained, "unexpected")); err != nil {
		t.Fatal("staging directory with unknown content was changed")
	}
	_, foreign, err := reopened.List(context.Background())
	if err != nil || len(foreign) != 1 || foreign[0].Name != stagingPrefix+"00000005" {
		t.Fatal("retained staging directory not quarantined", foreign, err)
	}
}

func TestProviderRecordFollowsConfigurationWithoutInstances(t *testing.T) {
	o, _ := fixture(t)
	b, err := openBackend(o, (&fakeProcesses{}).alive)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	changed := o
	changed.GPU = false
	changed.Binary = filepath.Join(filepath.Dir(o.Binary), "crosvm-2.exe")
	changed.Kernel = filepath.Join(filepath.Dir(o.Kernel), "vmlinuz-2")
	b, err = openBackend(changed, (&fakeProcesses{}).alive)
	if err != nil {
		t.Fatal("empty root rejected a new configuration", err)
	}
	current := b.Options()
	if err := createInstanceDirectory(current.Root, Envelope{Options: current, Record: recordFor(t, current, "1234abcd")}); err != nil {
		t.Fatal(err)
	}
	b.Close()
	if b, err := openBackend(o, (&fakeProcesses{}).alive); err == nil {
		b.Close()
		t.Fatal("configuration changed while an instance is retained")
	}
	b, err = openBackend(changed, (&fakeProcesses{}).alive)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
}

func TestCanonicalResolvesConfiguredPaths(t *testing.T) {
	o, _ := fixture(t)
	base := filepath.Dir(o.Root)
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "crosvm.exe"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := linkDirectory(real, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	o.Binary = filepath.Join(base, "link", "crosvm.exe")
	if _, err := o.Canonical(); err == nil {
		t.Fatal("missing root accepted")
	}
	if err := os.MkdirAll(o.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	c, err := o.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(filepath.Join(real, "crosvm.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(c.Binary, want) || strings.Contains(c.Binary, "link") {
		t.Fatal("binary link not resolved", c.Binary)
	}
	if again, err := c.Canonical(); err != nil || again != c {
		t.Fatal("canonical options are not stable", err)
	}
	if !sameImage(`\\?\C:\Tools\Crosvm\crosvm.exe`, `c:\tools\crosvm\CROSVM.EXE`) || sameImage(`C:\Tools\crosvm.exe`, `C:\Tools\other.exe`) {
		t.Fatal("image comparison is not case-insensitive over normalized paths")
	}
	if imageBase(`C:\Tools\crosvm.exe`) != "crosvm.exe" {
		t.Fatal("image base name")
	}
}

func TestNativeLogsAreCapped(t *testing.T) {
	var out strings.Builder
	w := &cappedWriter{w: &out, limit: 10}
	for range 3 {
		if n, err := w.Write([]byte("123456")); n != 6 || err != nil {
			t.Fatal("capped writer stopped draining", n, err)
		}
	}
	if out.String() != "1234561234" || !w.Exceeded() {
		t.Fatal("cap not enforced", out.String())
	}
	dir := t.TempDir()
	quiet := &cappedWriter{w: &out, limit: 10}
	if logLimitReached(dir, quiet) {
		t.Fatal("absent serial log reached limit")
	}
	if !logLimitReached(dir, w) {
		t.Fatal("exhausted native log ignored")
	}
	serial := filepath.Join(dir, "serial.log")
	if err := os.WriteFile(serial, []byte("123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if logLimitReached(dir, quiet) {
		t.Fatal("serial log below limit retired the guest")
	}
	if err := os.WriteFile(serial, []byte("1234567890"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !logLimitReached(dir, quiet) {
		t.Fatal("serial log at limit ignored")
	}
}

type deleteBackend struct {
	Backend
	deleted []string
}

func (b *deleteBackend) Delete(_ context.Context, name string) error {
	b.deleted = append(b.deleted, name)
	return nil
}

type forgetGuest struct {
	Guest
	forgotten []string
}

func (g *forgetGuest) Forget(id string) error { g.forgotten = append(g.forgotten, id); return nil }

func TestDeleteForgetsPinnedHostKeys(t *testing.T) {
	o, r := fixture(t)
	b, g := &deleteBackend{}, &forgetGuest{}
	p, err := New(o, b, g)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(context.Background(), r.Name); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b.deleted, []string{r.Name}) || !slices.Equal(g.forgotten, []string{r.Meta.InstanceID}) {
		t.Fatal("host key state not forgotten after deletion", b.deleted, g.forgotten)
	}
	dir := t.TempDir()
	for _, name := range []string{"1234abcd.known_hosts", "1234abcd.known_hosts.old", "89abcdef.known_hosts"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := ForgetHostKeys(dir, "1234abcd"); err != nil {
		t.Fatal(err)
	}
	if err := ForgetHostKeys(dir, "1234abcd"); err != nil {
		t.Fatal("forgetting is not idempotent", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "89abcdef.known_hosts" {
		t.Fatal("wrong known_hosts files removed", entries, err)
	}
	if ForgetHostKeys(dir, "../escape") == nil {
		t.Fatal("invalid instance ID accepted")
	}
}

// A deployment recorded before canonicalization names its root through a
// symlink (on Windows also another case, 8.3 names or a junction). Its
// provider record and retained instances stay usable, and the provider record
// is rewritten in canonical form.
func TestNonCanonicalRecordsRemainOwned(t *testing.T) {
	o, _ := fixture(t)
	base := filepath.Dir(o.Root)
	real := filepath.Join(base, "real-instances")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := linkDirectory(real, o.Root); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(real, "provider.json", o); err != nil {
		t.Fatal(err)
	}
	r := recordFor(t, o, "89abcdef")
	if err := createInstanceDirectory(o.Root, Envelope{Options: o, Record: r}); err != nil {
		t.Fatal(err)
	}
	b, err := openBackend(o, (&fakeProcesses{}).alive)
	if err != nil {
		t.Fatal("recorded non-canonical configuration refused", err)
	}
	defer b.Close()
	current := b.Options()
	if current == o {
		t.Fatal("fixture paths are already canonical")
	}
	var pinned Options
	if err := readJSON(filepath.Join(real, "provider.json"), &pinned); err != nil || pinned != current {
		t.Fatal("provider record not rewritten in canonical form", pinned, err)
	}
	p, err := New(current, b, &forgetGuest{})
	if err != nil {
		t.Fatal(err)
	}
	if status, err := p.Status(context.Background(), r.Name); err != nil || !status.Exists || !status.Owned {
		t.Fatal("retained instance stranded", status, err)
	}
	owned, foreign, err := p.List(context.Background())
	if err != nil || len(owned) != 1 || len(foreign) != 0 {
		t.Fatal("retained instance not listed as owned", owned, foreign, err)
	}
	// Another configuration is still refused while the instance is retained.
	b.Close()
	changed := o
	changed.GPU = false
	if other, err := openBackend(changed, (&fakeProcesses{}).alive); err == nil {
		other.Close()
		t.Fatal("configuration changed while an instance is retained")
	}
	b, err = openBackend(o, (&fakeProcesses{}).alive)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := writeJSON(filepath.Join(real, "89abcdef"), "native.json", NativeState{Phase: "failed", Empty: true}); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(context.Background(), r.Name); err != nil {
		t.Fatal("retained instance cannot be cleaned up", err)
	}
	if _, err := os.Stat(filepath.Join(real, "89abcdef")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("instance directory remains")
	}
}
