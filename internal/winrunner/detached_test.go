package winrunner

import (
	"errors"
	"testing"
)

func TestTrampolineClaimMatrix(t *testing.T) {
	for _, mode := range []string{"premature", "missing-mode", "invalid-mode", "claim", "cancelled", "listener", "lab-probe", "launch-failed"} {
		t.Run(mode, func(t *testing.T) {
			root := guestTestRoot(t)
			write := func(name, value string) {
				t.Helper()
				if err := root.WriteFile(name, []byte(value), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "premature" {
				write("launched", "")
			}
			if mode != "missing-mode" {
				value := "listener"
				if mode == "invalid-mode" {
					value = "listener\n"
				}
				if mode == "lab-probe" {
					value = mode
				}
				write("launch-mode", value)
			}
			if mode == "claim" {
				write("detached.claim", "")
			}
			if mode == "cancelled" {
				write("cancelled", "")
			}
			calls := 0
			launch := func(value string) error {
				calls++
				if value != "listener" && value != "lab-probe" {
					t.Fatal("unvalidated launch")
				}
				if mode == "launch-failed" {
					return errors.New("failed")
				}
				return nil
			}
			err := claimDetached(root, launch)
			wantLaunch := mode == "listener" || mode == "lab-probe" || mode == "launch-failed"
			wantErr := mode == "missing-mode" || mode == "invalid-mode" || mode == "launch-failed"
			if (calls == 1) != wantLaunch || (err != nil) != wantErr {
				t.Fatal("claim decision differs", calls, err)
			}
			claimed, e := guestFileExists(root, "detached.claim")
			if e != nil || claimed != (wantLaunch || mode == "claim" || mode == "cancelled") {
				t.Fatal("claim consumed incorrectly", e)
			}
			if wantLaunch {
				if err := claimDetached(root, launch); err != nil || calls != 1 {
					t.Fatal("trampoline replayed")
				}
			}
		})
	}
}

func TestStopBeforeListenerPersistsCancellation(t *testing.T) {
	root := guestTestRoot(t)
	for range 2 {
		if err := stopGuest(root, func() error { t.Fatal("absent listener cancelled"); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	exists, err := guestFileExists(root, "cancelled")
	if err != nil || !exists {
		t.Fatal("stop lost cancellation")
	}
	recorded := false
	err = listenerCancellation(func() (bool, error) { return exists, nil }, func() error { recorded = true; return nil })
	if err == nil || !recorded {
		t.Fatal("listener ignored cancellation")
	}
}

func TestLaunchModePrecedesMarker(t *testing.T) {
	root := guestTestRoot(t)
	if err := root.WriteFile("jit", []byte("synthetic input"), 0o600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("interrupted between mode and marker")
	err := markAndLaunchWithMode(root, "lab-probe", func() error {
		if exists, e := guestFileExists(root, "launched"); e != nil || exists {
			t.Fatal("marker preceded mode publication")
		}
		if e := publishLaunchMode(root, "lab-probe"); e != nil {
			t.Fatal(e)
		}
		return injected
	}, func() error { t.Fatal("interrupted launch dispatched"); return nil })
	if !errors.Is(err, injected) {
		t.Fatal("missing injected failure", err)
	}
	if raw, e := root.ReadFile("launch-mode"); e != nil || string(raw) != "lab-probe" {
		t.Fatal("mode was not published")
	}
	if exists, e := guestFileExists(root, "launched"); e != nil || exists {
		t.Fatal("interruption still published marker")
	}
	if e := claimDetached(root, func(string) error { t.Fatal("premature trampoline launched"); return nil }); e != nil {
		t.Fatal(e)
	}
	if exists, e := guestFileExists(root, "detached.claim"); e != nil || exists {
		t.Fatal("premature trampoline claimed launch")
	}
	if _, err := root.Stat("launch-mode.new"); err == nil {
		t.Fatal("temporary mode remained")
	}
}

func TestCancellationPublicationInterleavings(t *testing.T) {
	for _, order := range []string{"stop before publication", "stop after publication", "stop after recheck"} {
		t.Run(order, func(t *testing.T) {
			root := guestTestRoot(t)
			stopSignals, listenerSignals := 0, 0
			stop := func() {
				t.Helper()
				if err := stopGuest(root, func() error { stopSignals++; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			err := publishListenerAndCheckCancellation(root, func() error {
				if order == "stop before publication" {
					stop()
				}
				if err := root.WriteFile("listener.json", []byte("public identity fixture"), 0o600); err != nil {
					return err
				}
				if order == "stop after publication" {
					stop()
				}
				return nil
			}, func() error { listenerSignals++; return nil })
			if err != nil {
				t.Fatal(err)
			}
			if order == "stop after recheck" {
				stop()
			}
			if stopSignals+listenerSignals == 0 {
				t.Fatal("cancellation was lost")
			}
			if order == "stop before publication" && (stopSignals != 0 || listenerSignals != 1) {
				t.Fatal("listener failed to self-cancel")
			}
			if order == "stop after recheck" && (stopSignals != 1 || listenerSignals != 0) {
				t.Fatal("stop missed published listener")
			}
		})
	}
}
