//go:build windows

package imagefactory

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestFailureShutdownOrderingAndBound(t *testing.T) {
	for _, mode := range []string{"request-refused", "request-timeout", "guest-exits", "guest-never-exits", "wait-error"} {
		t.Run(mode, func(t *testing.T) {
			var calls []string
			parent, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			terminated := errors.New("fixture terminate result")
			begun := time.Now()
			err := terminateAfterGuestFailure(parent, 20*time.Millisecond, func(ctx context.Context) error {
				calls = append(calls, "request")
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 20*time.Millisecond {
					t.Fatal("request unbounded")
				}
				if mode == "request-timeout" {
					<-ctx.Done()
					return ctx.Err()
				}
				if mode == "request-refused" {
					return errors.New("private request error")
				}
				return nil
			}, func(ctx context.Context) error {
				calls = append(calls, "wait")
				if mode == "guest-never-exits" {
					<-ctx.Done()
					return ctx.Err()
				}
				if mode == "wait-error" {
					return errors.New("private wait error")
				}
				return nil
			}, func() error {
				calls = append(calls, "terminate")
				if parent.Err() != nil {
					t.Fatal("grace canceled cleanup")
				}
				return terminated
			})
			want := []string{"request", "wait", "terminate"}
			if mode == "request-refused" || mode == "request-timeout" {
				want = []string{"request", "terminate"}
			}
			if !slices.Equal(calls, want) || !errors.Is(err, terminated) || time.Since(begun) > 500*time.Millisecond {
				t.Fatal("failure cleanup order or bound changed")
			}
		})
	}
}

func TestFailureShutdownAgentArguments(t *testing.T) {
	called := false
	dial := fakeFactoryAgent(func(argv []string, input []byte) ([]byte, int) {
		called = slices.Equal(argv, []string{`C:\Windows\System32\shutdown.exe`, "/s", "/t", "5", "/d", "p:0:0"}) && len(input) == 0
		return []byte("private ignored output"), 0
	})
	if err := requestFailureShutdown(t.Context(), dial); err != nil || !called {
		t.Fatal("shutdown argv or output handling changed")
	}
}

func TestFailureShutdownEligibility(t *testing.T) {
	for _, tc := range []struct {
		name           string
		started        bool
		failure, cause error
		want           bool
	}{
		{"preparation failure", true, errors.New("failure"), nil, true},
		{"build deadline", true, context.DeadlineExceeded, context.DeadlineExceeded, true},
		{"no preparation", false, errors.New("failure"), nil, false},
		{"success", true, nil, nil, false},
		{"reserve cause", true, context.Canceled, &memoryReserveLostError{}, false},
		{"joined reserve failure", true, errors.Join(context.Canceled, &memoryReserveLostError{}), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if allowFailureShutdown(tc.started, tc.failure, tc.cause) != tc.want {
				t.Fatal("failure shutdown eligibility changed")
			}
		})
	}
}

func TestCleanupStageReserves(t *testing.T) {
	cleanup, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	stop, cancelStop := cleanupStageContext(cleanup, 120*time.Millisecond)
	defer cancelStop()
	grace, cancelGrace := cleanupStageContext(stop, 50*time.Millisecond)
	defer cancelGrace()
	called := false
	if err := terminateAfterGuestFailure(grace, failureShutdownBudget, func(context.Context) error { return nil }, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}, func() error {
		called = true
		if stop.Err() != nil {
			t.Fatal("grace exhausted termination budget")
		}
		return nil
	}); err != nil || !called {
		t.Fatal("termination missing")
	}
	diagnostics, cancelDiagnostics := cleanupStageContext(cleanup, 60*time.Millisecond)
	defer cancelDiagnostics()
	<-diagnostics.Done()
	if cleanup.Err() != nil {
		t.Fatal("diagnostics exhausted detach budget")
	}
	end, _ := cleanup.Deadline()
	diagEnd, _ := diagnostics.Deadline()
	if end.Sub(diagEnd) != 60*time.Millisecond {
		t.Fatal("detach time not reserved")
	}
	// An already-used grace allocation must not start a request at all.
	if err := terminateAfterGuestFailure(diagnostics, failureShutdownBudget, func(context.Context) error { t.Fatal("expired grace requested shutdown"); return nil }, nil, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
