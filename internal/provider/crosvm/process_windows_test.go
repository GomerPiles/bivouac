//go:build windows

package crosvm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// This native fixture uses only subprocesses of the test executable. No VM,
// administrator token, installed service or GitHub credential is involved.
func TestNativeFixture(t *testing.T) {
	mode := os.Getenv("BIVOUAC_NATIVE_FIXTURE")
	if mode == "" {
		return
	}
	if mode == "parent" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(self, "-test.run=^TestNativeFixture$")
		cmd.Env = append(os.Environ(), "BIVOUAC_NATIVE_FIXTURE=child")
		hideSupervisor(cmd)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pid := cmd.Process.Pid
		if pid < 1 || uint64(pid) > 0xffffffff {
			t.Fatal("invalid fixture child PID")
			return
		}
		identity, live, err := Identity(uint32(pid))
		if err != nil || !live {
			t.Fatal("fixture child unavailable")
		}
		data, err := json.Marshal(identity)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(os.Getenv("BIVOUAC_NATIVE_FIXTURE_RECORD"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(2 * time.Minute)
}

// A running image reports its final path, not the link it was started
// through, so recorded VM images match only a canonical configured binary.
func TestCanonicalBinaryMatchesRunningImage(t *testing.T) {
	o, _ := fixture(t)
	if err := os.MkdirAll(o.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(filepath.Dir(o.Root), "real-tools")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "crosvm.exe"), image, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := linkDirectory(real, filepath.Dir(o.Binary)); err != nil {
		t.Fatal(err)
	}
	c, err := o.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(o.Binary, "-test.run=^TestNativeFixture$")
	cmd.Env = append(os.Environ(), "BIVOUAC_NATIVE_FIXTURE=child")
	hideSupervisor(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := cmd.Process.Pid
	if pid < 1 || uint64(pid) > 0xffffffff {
		t.Fatal("invalid linked fixture PID")
		return
	}
	identity, live, err := Identity(uint32(pid))
	if err != nil || !live {
		t.Fatal("linked fixture unavailable", err)
	}
	if !sameImage(identity.Image, c.Binary) {
		t.Fatal("canonical binary differs from the running image", identity.Image, c.Binary)
	}
	if sameImage(identity.Image, o.Binary) {
		t.Fatal("running image kept the link spelling", identity.Image)
	}
}

func nativeFixture(t *testing.T, r Record) (*nativeChild, ProcessIdentity) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "child.json")
	child, err := startJob(self, []string{"-test.run=^TestNativeFixture$"}, []string{"BIVOUAC_NATIVE_FIXTURE=parent", "BIVOUAC_NATIVE_FIXTURE_RECORD=" + path}, jobName(r), io.Discard, io.Discard, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Close() })
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var descendant ProcessIdentity
		if readJSON(path, &descendant) == nil {
			return child, descendant
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("native fixture descendant did not start")
	return nil, ProcessIdentity{}
}

func confirmAbsent(t *testing.T, identities ...ProcessIdentity) {
	t.Helper()
	for _, identity := range identities {
		deadline := time.Now().Add(10 * time.Second)
		for {
			live, err := sameProcess(identity)
			// Job close initiates termination asynchronously. Windows can deny
			// process queries while the exiting PID still appears in its snapshot;
			// keep waiting for positive absence rather than accepting that error.
			if err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				t.Fatal(err)
			}
			if err == nil && !live {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("owned native process survived job termination")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func TestNativeJobCloseKillsEntireOwnedTree(t *testing.T) {
	_, r := fixture(t)
	child, descendant := nativeFixture(t, r)
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	confirmAbsent(t, child.identity, descendant)
}

func TestNativeRecoveryAndJobNameCollision(t *testing.T) {
	_, r := fixture(t)
	child, descendant := nativeFixture(t, r)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	second, err := startJob(self, nil, nil, jobName(r), io.Discard, io.Discard, func() error { t.Fatal("collision reached journal"); return nil })
	if err == nil || second != nil {
		t.Fatal("preexisting job adopted")
	}
	if live, err := sameProcess(child.identity); err != nil || !live {
		t.Fatal("collision affected original job")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := recoverJob(ctx, r); err != nil {
		t.Fatal(err)
	}
	confirmAbsent(t, child.identity, descendant)
}

func TestNativeJournalFailureLaunchesNothing(t *testing.T) {
	_, r := fixture(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child, err := startJob(self, nil, nil, jobName(r), io.Discard, io.Discard, func() error { return errors.New("journal fixture failure") })
	if err == nil || child != nil {
		t.Fatal("failed journal created child")
	}
	if err := recoverJob(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}
