package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestConcurrentAtomicReaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	if err := WriteAtomic(path, []byte(`{"generation":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				data, err := ReadFile(path)
				if err != nil || !json.Valid(data) {
					t.Errorf("read exposed missing/partial state: %v", err)
					return
				}
			}
		}()
	}
	for i := range 100 {
		data, err := json.Marshal(map[string]int{"generation": i})
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteAtomic(path, data, 0o600); err != nil {
			t.Error(err)
			break
		}
	}
	close(stop)
	wg.Wait()
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, func() string { return "ctl-1" })
	if err != nil {
		t.Fatal(err)
	}
	inst := &Instance{ID: "a", Provider: "macos", Name: "bivouac-macos-a", Phase: PhaseCreating, CreatedAt: time.Now()}
	if err := s.Put(inst); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update("a", func(i *Instance) { i.Phase = PhaseListening }); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordError("a", "boom"); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir, func() string { return "ctl-2" })
	if err != nil {
		t.Fatal(err)
	}
	if again.ControllerID() != "ctl-1" {
		t.Fatalf("controller id changed: %s", again.ControllerID())
	}
	got, ok := again.Get("a")
	if !ok || got.Phase != PhaseListening {
		t.Fatalf("instance not persisted: %+v", got)
	}
	if errs := again.Errors(); len(errs) != 1 || errs[0].Message != "boom" {
		t.Fatalf("errors not persisted: %+v", errs)
	}
	if err := again.Remove("a"); err != nil {
		t.Fatal(err)
	}
	if len(again.List()) != 0 {
		t.Fatal("remove did not persist")
	}
}

func TestFailedUpdateDoesNotReleaseReservation(t *testing.T) {
	s, err := Open(t.TempDir(), func() string { return "ctl" })
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(&Instance{ID: "a", Phase: PhaseDestroying, Job: &Job{RunID: 1}}); err != nil {
		t.Fatal(err)
	}
	// Replacing a directory cannot succeed, even when tests run as root.
	originalPath := s.path
	s.path = filepath.Join(filepath.Dir(s.path), "directory")
	if err := os.Mkdir(s.path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update("a", func(i *Instance) { i.Phase = PhaseDeregistering; i.GuestDeletedAt = time.Now(); i.Job.RunID = 2 }); err == nil {
		t.Fatal("update unexpectedly persisted")
	}
	got, _ := s.Get("a")
	if got.Phase != PhaseDestroying || !got.GuestDeletedAt.IsZero() || got.Job.RunID != 1 {
		t.Fatal("failed durable update changed resource reservation")
	}
	if err := s.Remove("a"); err == nil {
		t.Fatal("removal unexpectedly persisted")
	}
	if _, exists := s.Get("a"); !exists {
		t.Fatal("failed removal lost the cleanup retry record")
	}
	again, err := Open(filepath.Dir(originalPath), func() string { return "unused" })
	if err != nil {
		t.Fatal(err)
	}
	durable, _ := again.Get("a")
	if durable.Phase != got.Phase {
		t.Fatal("memory and durable reservation disagree")
	}
}
