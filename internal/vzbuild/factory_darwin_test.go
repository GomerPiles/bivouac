package vzbuild

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/vm"
	"github.com/GomerPiles/bivouac/internal/vzrecipe"
	"golang.org/x/sys/unix"
)

func factoryFixture(t *testing.T) *factory {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "vf-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	state := t.TempDir()
	f, err := openFactory(dir, control.Files{Dir: state})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.lock.Close() })
	f.stop = func(context.Context, string) error { return nil }
	return f
}
func buildManifestFixture(t *testing.T, dir string, built bool) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	m, err := vm.NewLinuxManifest(4, 4)
	if err != nil {
		t.Fatal(err)
	}
	if built {
		r := vzrecipe.Registry()[0]
		m.Build = &vm.Build{Recipe: r.Name, SourceURL: r.Source.URLs[0], SourceSHA256: r.Source.SHA256, RunnerURL: r.Runner.URLs[0], RunnerSHA256: r.Runner.SHA256, HelperSHA256: strings.Repeat("a", 64), HostSHA256: strings.Repeat("b", 64), DiskBytes: 64 * vzrecipe.GiB}
	}
	if err := vm.WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
}
func stageFixture(t *testing.T, f *factory) factoryRecord {
	t.Helper()
	r := factoryRecord{Owner: factoryOwner, ID: strings.Repeat("a", 32), Recipe: vzrecipe.DefaultName, Target: "baseline", Phase: "staging", BuildDir: ".build-" + strings.Repeat("a", 32), GateDir: ".gate-" + strings.Repeat("a", 32)}
	path := f.store.Dir(".build-" + r.ID)
	buildManifestFixture(t, path, true)
	var err error
	r.Build, err = fileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRecord(f.dir, r); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestFactoryLockAndUnrecordedDirectoryRefusal(t *testing.T) {
	f := factoryFixture(t)
	if other, err := openFactory(string(f.store), f.daemon); err == nil {
		_ = other.lock.Close()
		t.Fatal("second builder acquired lock")
	}
	unrecorded := f.store.Dir(".build-" + strings.Repeat("b", 32))
	if err := os.Mkdir(unrecorded, 0700); err != nil {
		t.Fatal(err)
	}
	if FactoryStatus(string(f.store)) == nil {
		t.Fatal("doctor missed leftovers")
	}
	if err := f.recover(context.Background()); err != nil || len(f.warnings) == 0 {
		t.Fatal("unrecorded state was not reported without blocking", err)
	}
	if _, err := os.Stat(unrecorded); err != nil {
		t.Fatal("unrecorded directory removed")
	}
}
func TestFactoryRecordedRecoveryAndForeignHolderRefusal(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "stopped", true: "foreign-holder"}[foreign], func(t *testing.T) {
			f := factoryFixture(t)
			r := stageFixture(t, f)
			calls := 0
			f.stop = func(_ context.Context, path string) error {
				calls++
				if path != f.store.Dir(".build-"+r.ID) {
					t.Error("stopped unrecorded directory")
				}
				if foreign {
					return vm.ErrForeignHolder
				}
				return nil
			}
			err := f.recover(context.Background())
			if foreign {
				if err != nil || !errors.Is(errors.Join(f.warnings...), vm.ErrForeignHolder) {
					t.Fatal("foreign lock holder not refused", err)
				}
				if _, err := os.Stat(f.store.Dir(".build-" + r.ID)); err != nil {
					t.Fatal("foreign-held directory removed")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if FactoryStatus(string(f.store)) != nil {
					t.Fatal("recovery left state")
				}
			}
			if calls != 1 {
				t.Fatal("missing stop proof")
			}
		})
	}
}
func TestFactoryRefusesChangedDirectoryIdentity(t *testing.T) {
	f := factoryFixture(t)
	r := stageFixture(t, f)
	dir := f.store.Dir(".build-" + r.ID)
	if err := os.Rename(dir, dir+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := f.recover(context.Background()); err != nil || len(f.warnings) == 0 {
		t.Fatal("changed identity not reported", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("unrecognized directory deleted")
	}
}
func TestPublicationNeverOverwritesAndReplacementGuards(t *testing.T) {
	t.Run("exclusive", func(t *testing.T) {
		f := factoryFixture(t)
		r := stageFixture(t, f)
		buildManifestFixture(t, f.store.Dir(r.Target), false)
		before, _ := fileIdentity(f.store.Dir(r.Target))
		if f.publish(&r, false) == nil {
			t.Fatal("exclusive publication overwrote target")
		}
		after, _ := fileIdentity(f.store.Dir(r.Target))
		if before != after {
			t.Fatal("target changed")
		}
	})
	t.Run("publish", func(t *testing.T) {
		f := factoryFixture(t)
		r := stageFixture(t, f)
		if err := f.publish(&r, false); err != nil {
			t.Fatal(err)
		}
		id, err := fileIdentity(f.store.Dir(r.Target))
		if err != nil || id != r.Build {
			t.Fatal("wrong published identity")
		}
		if FactoryStatus(string(f.store)) != nil {
			t.Fatal("published factory left state")
		}
	})
	for _, kind := range []string{"import", "daemon", "replace"} {
		t.Run(kind, func(t *testing.T) {
			f := factoryFixture(t)
			r := stageFixture(t, f)
			buildManifestFixture(t, f.store.Dir(r.Target), kind != "import")
			var release func()
			if kind == "daemon" {
				lock, err := f.daemon.Acquire()
				if err != nil {
					t.Fatal(err)
				}
				release = func() { _ = lock.Release() }
			}
			if release != nil {
				defer release()
			}
			err := f.publish(&r, true)
			if kind == "replace" {
				if err != nil {
					t.Fatal(err)
				}
				id, _ := fileIdentity(f.store.Dir(r.Target))
				if id != r.Build {
					t.Fatal("wrong replacement identity")
				}
				if FactoryStatus(string(f.store)) != nil {
					t.Fatal("retired VM retained")
				}
			} else if err == nil {
				t.Fatal("unsafe replacement accepted")
			}
		})
	}
}
func TestRecoveryPublicationIntentBeforeAndAfterRename(t *testing.T) {
	for _, replace := range []bool{false, true} {
		for _, renamed := range []bool{false, true} {
			name := "new"
			if replace {
				name = "replace"
			}
			if renamed {
				name += "-renamed"
			}
			t.Run(name, func(t *testing.T) {
				f := factoryFixture(t)
				r := stageFixture(t, f)
				r.New = r.Build
				r.Phase = "publish"
				if replace {
					buildManifestFixture(t, f.store.Dir(r.Target), true)
					r.Old, _ = fileIdentity(f.store.Dir(r.Target))
					r.Phase = "swap"
				}
				if err := writeRecord(f.dir, r); err != nil {
					t.Fatal(err)
				}
				if renamed {
					flags := uint32(unix.RENAME_EXCL)
					if replace {
						flags = unix.RENAME_SWAP
					}
					if err := unix.RenamexNp(f.store.Dir(".build-"+r.ID), f.store.Dir(r.Target), flags); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.recover(context.Background()); err != nil {
					t.Fatal(err)
				}
				target, err := identityOrAbsent(f.store.Dir(r.Target))
				if err != nil {
					t.Fatal(err)
				}
				want := identity{}
				if replace {
					want = r.Old
				}
				if renamed {
					want = r.New
				}
				if target != want {
					t.Fatal("recovery changed published target")
				}
				if FactoryStatus(string(f.store)) != nil {
					t.Fatal("recovery left staging")
				}
			})
		}
	}
}
func TestFactoryRecordAndUnknownFilesAreRetained(t *testing.T) {
	f := factoryFixture(t)
	path := filepath.Join(f.dir, "unknown")
	if err := os.WriteFile(path, []byte("unknown"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.recover(context.Background()); err != nil || len(f.warnings) == 0 {
		t.Fatal("unknown record not reported", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("unknown record deleted")
	}
}

func TestReplacementRefusesExternalManifestLock(t *testing.T) {
	if path := os.Getenv("BIVOUAC_FACTORY_TEST_LOCK"); path != "" {
		lock, err := vm.Acquire(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Release() }()
		_, _ = os.Stdin.Read(make([]byte, 1))
		return
	}
	f := factoryFixture(t)
	r := stageFixture(t, f)
	target := f.store.Dir(r.Target)
	buildManifestFixture(t, target, true)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestReplacementRefusesExternalManifestLock$")
	cmd.Env = append(os.Environ(), "BIVOUAC_FACTORY_TEST_LOCK="+target)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close(); _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		pid, err := vm.Holder(target)
		if err != nil {
			t.Fatal(err)
		}
		if pid == cmd.Process.Pid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lock child did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if f.publish(&r, true) == nil {
		t.Fatal("locked baseline replaced")
	}
	if err := stopFactoryVM(context.Background(), target); !errors.Is(err, vm.ErrForeignHolder) {
		t.Fatal("factory cleanup did not refuse foreign holder", err)
	}
}

func TestFactoryCloneRetainsProvenanceAndPublicCloneRejectsHiddenNames(t *testing.T) {
	f := factoryFixture(t)
	r := stageFixture(t, f)
	build := ".build-" + r.ID
	gate := ".gate-" + r.ID
	for _, name := range []string{vm.DiskFile, vm.NVRAMFile} {
		if err := os.WriteFile(filepath.Join(f.store.Dir(build), name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if f.store.Clone(build, "public-clone", vm.CloneOptions{}) == nil {
		t.Fatal("public Clone accepted a hidden source")
	}
	if err := f.store.CloneFactory(build, gate); err != nil {
		t.Fatal(err)
	}
	before, err := vm.ReadManifest(f.store.Dir(build))
	if err != nil {
		t.Fatal(err)
	}
	after, err := vm.ReadManifest(f.store.Dir(gate))
	if err != nil {
		t.Fatal(err)
	}
	if after.Build == nil || *before.Build != *after.Build || before.MAC == after.MAC {
		t.Fatal("factory clone lost provenance or reused MAC")
	}
	// A published baseline's ordinary runner clones retain the same provenance.
	if err := os.Rename(f.store.Dir(build), f.store.Dir("baseline")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Clone("baseline", "bivouac-test-fixture", vm.CloneOptions{}); err != nil {
		t.Fatal(err)
	}
	ordinary, err := vm.ReadManifest(f.store.Dir("bivouac-test-fixture"))
	if err != nil || ordinary.Build == nil || *ordinary.Build != *before.Build {
		t.Fatal("runner clone lost provenance", err)
	}
}

func TestRecoveryCleansOwnedTempsAndCreationWindows(t *testing.T) {
	for _, shape := range []string{"empty", "expected", "unrecognized", "symlink"} {
		t.Run(shape, func(t *testing.T) {
			f := factoryFixture(t)
			r := factoryRecord{Owner: factoryOwner, ID: strings.Repeat("c", 32), Recipe: vzrecipe.DefaultName, Target: "baseline", Phase: "staging", BuildDir: ".build-" + strings.Repeat("c", 32), GateDir: ".gate-" + strings.Repeat("c", 32)}
			// The persisted intent precedes either mkdir; no inode update has happened.
			if err := writeRecord(f.dir, r); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{r.BuildDir, r.GateDir} {
				dir := f.store.Dir(name)
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				switch shape {
				case "expected":
					if err := os.WriteFile(filepath.Join(dir, vm.DiskFile), []byte("partial"), 0600); err != nil {
						t.Fatal(err)
					}
				case "unrecognized":
					if err := os.WriteFile(filepath.Join(dir, "foreign"), nil, 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Symlink("/does-not-exist", filepath.Join(dir, vm.DiskFile)); err != nil {
						t.Fatal(err)
					}
				}
			}
			temp := filepath.Join(f.dir, ".record-stale")
			if err := os.WriteFile(temp, []byte("partial"), 0600); err != nil {
				t.Fatal(err)
			}
			inputs := t.TempDir()
			inputTemp := filepath.Join(inputs, ".input-stale")
			if err := os.WriteFile(inputTemp, []byte("partial"), 0600); err != nil {
				t.Fatal(err)
			}
			digestFile := filepath.Join(inputs, strings.Repeat("a", 64))
			if err := os.WriteFile(digestFile, []byte("retained"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := f.recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := f.recoverInputs(inputs); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{temp, inputTemp} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("owned temporary file retained")
				}
			}
			if _, err := os.Stat(digestFile); err != nil {
				t.Fatal("verified input removed")
			}
			for _, name := range []string{r.BuildDir, r.GateDir} {
				_, err := os.Stat(f.store.Dir(name))
				if shape == "empty" || shape == "expected" {
					if !os.IsNotExist(err) {
						t.Fatal("creation window blocked recovery")
					}
				} else if err != nil || len(f.warnings) == 0 {
					t.Fatal("unrecognized contents removed or unreported", err)
				}
			}
		})
	}
}
func TestRecoveryExclusiveCollisionDiscardsOnlyCandidate(t *testing.T) {
	f := factoryFixture(t)
	r := stageFixture(t, f)
	buildManifestFixture(t, f.store.Dir(r.Target), false)
	target, err := fileIdentity(f.store.Dir(r.Target))
	if err != nil {
		t.Fatal(err)
	}
	if f.publish(&r, false) == nil {
		t.Fatal("collision overwrote target")
	}
	if err := f.recover(context.Background()); err != nil || len(f.warnings) > 0 {
		t.Fatal("exclusive collision left recovery ambiguous", err)
	}
	got, err := fileIdentity(f.store.Dir(r.Target))
	if err != nil || got != target {
		t.Fatal("collision cleanup touched target", err)
	}
	if _, err := os.Stat(f.store.Dir(r.BuildDir)); !os.IsNotExist(err) {
		t.Fatal("unpublished candidate retained")
	}
}
func TestRecoveryReportsUnknownStateAndContinues(t *testing.T) {
	f := factoryFixture(t)
	r := stageFixture(t, f)
	unknown := f.store.Dir(".gate-" + strings.Repeat("b", 32))
	if err := os.Mkdir(unknown, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "unknown"), []byte("unknown"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.recover(context.Background()); err != nil || len(f.warnings) != 2 {
		t.Fatal("unknown state blocked recognized recovery", err)
	}
	if _, err := os.Stat(f.store.Dir(r.BuildDir)); !os.IsNotExist(err) {
		t.Fatal("unrelated recorded build was not recovered")
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatal("unknown directory removed")
	}
	if err := f.advisoryTarget("unrelated", false); err != nil {
		t.Fatal("unknown state blocked another target", err)
	}
}
func TestAdvisoryTargetPreconditionsAndHistoricalReplace(t *testing.T) {
	f := factoryFixture(t)
	if err := f.advisoryTarget("missing", true); err == nil {
		t.Fatal("replacement of missing target accepted")
	}
	path := f.store.Dir("imported")
	buildManifestFixture(t, path, false)
	if f.advisoryTarget("imported", true) == nil || f.advisoryTarget("imported", false) == nil {
		t.Fatal("existing import precondition missed")
	}
	path = f.store.Dir("old")
	buildManifestFixture(t, path, true)
	m, err := vm.ReadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	m.Build.SourceSHA256 = strings.Repeat("c", 64)
	m.Build.Recipe = "historical"
	m.Guest.AgentVersion++
	if err := vm.WriteManifest(path, m); err != nil {
		t.Fatal(err)
	}
	if err := f.advisoryTarget("old", true); err != nil {
		t.Fatal("stale baseline cannot be replaced", err)
	}
	lock, err := f.daemon.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()
	if f.advisoryTarget("old", true) == nil {
		t.Fatal("advisory daemon check missed held lock")
	}
}
func TestRecoveryArchivesBoundedLaunchLogBeforeDiscard(t *testing.T) {
	f := factoryFixture(t)
	f.logs = t.TempDir()
	r := stageFixture(t, f)
	body := strings.Repeat("fixed host status\n", 100000)
	if err := os.WriteFile(filepath.Join(f.store.Dir(r.BuildDir), "launch.log"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.recoverRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if len(f.archived) != 1 {
		t.Fatal("log was not archived")
	}
	log, err := os.ReadFile(f.archived[0])
	if err != nil || len(log) == 0 || len(log) > 1<<20 {
		t.Fatal("launch log was lost or unbounded", err)
	}
	if _, err := os.Stat(f.store.Dir(r.BuildDir)); !os.IsNotExist(err) {
		t.Fatal("staging not discarded")
	}
}

func TestFactoryStartupErrorPreservesCauseAndArchivesStatus(t *testing.T) {
	f := factoryFixture(t)
	f.logs = t.TempDir()
	r := stageFixture(t, f)
	dir := f.store.Dir(r.BuildDir)
	err := provisionVM(context.Background(), filepath.Join(t.TempDir(), "missing-helper"), vm.RunOptions{Dir: dir})
	if err == nil || !errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "guest-initiated") {
		t.Fatal("startup cause or classification lost", err)
	}
	if err := f.recoverRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if len(f.archived) != 1 {
		t.Fatal("startup launch log was not preserved")
	}
}

func TestArchiveFlushesPartialHostStatusLine(t *testing.T) {
	f := factoryFixture(t)
	r := stageFixture(t, f)
	f.logs = t.TempDir()
	const status = "helper startup failed without a newline"
	if err := os.WriteFile(filepath.Join(f.store.Dir(r.BuildDir), "launch.log"), []byte(status), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.recoverRecord(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if len(f.archived) != 1 {
		t.Fatal("launch log missing")
	}
	got, err := os.ReadFile(f.archived[0])
	if err != nil || string(got) != status {
		t.Fatal("partial host status line lost", err)
	}
}
