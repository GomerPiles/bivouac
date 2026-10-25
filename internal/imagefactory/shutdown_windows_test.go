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
