//go:build windows

package hcs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestErrorsCarryOnlyOperationAndHRESULT(t *testing.T) {
	for _, code := range []uint32{uint32(windows.HCS_E_OPERATION_TIMEOUT), uint32(windows.HCS_E_OPERATION_PENDING)} {
		err := hresult("HcsCreateComputeSystem", uintptr(code))
		if err == nil || !OutcomeUnknown(err) {
			t.Fatal("pending native create treated as settled")
		}
		if !strings.HasPrefix(err.Error(), "HcsCreateComputeSystem HRESULT 0x") {
			t.Fatal("unexpected native error format", err)
		}
	}
	if !OutcomeUnknown(context.Canceled) || !OutcomeUnknown(context.DeadlineExceeded) {
		t.Fatal("canceled wait treated as settled")
	}
	if OutcomeUnknown(hresult("HcsCreateComputeSystem", uintptr(0x80070005))) || OutcomeUnknown(nil) || OutcomeUnknown(ErrNotFound) {
		t.Fatal("terminal result treated as pending")
	}
	if hresult("HcsCreateComputeSystem", 0) != nil || hresult("HcsCreateComputeSystem", 1) != nil {
		t.Fatal("successful HRESULT rejected")
	}
}

func TestWaitBoundFollowsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := waitBound(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled operation admitted")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	bound, err := waitBound(ctx)
	if err != nil || bound == 0 || bound > 100 {
		t.Fatalf("deadline not clipped: %d %v", bound, err)
	}
	if bound, err = waitBound(context.Background()); err != nil || bound != 120000 {
		t.Fatalf("missing deadline not bounded: %d %v", bound, err)
	}
}

func TestBoundedUTF16Result(t *testing.T) {
	words := []uint16{'o', 'k', 0}
	b, err := boundedResult(&words[0])
	if err != nil || string(b) != "ok" {
		t.Fatalf("unexpected bounded native result: %q %v", b, err)
	}
	unterminated := make([]uint16, 32768)
	for i := range unterminated {
		unterminated[i] = 'x'
	}
	if _, err = boundedResult(&unterminated[0]); err == nil {
		t.Fatal("unbounded native result accepted")
	}
	if b, err = boundedResult(nil); b != nil || err != nil {
		t.Fatal("absent result not empty")
	}
}

func TestWaitExitRetriesTimeoutsAndRejectsErrors(t *testing.T) {
	calls := 0
	status, err := waitExit(context.Background(), func(timeout uintptr) ([]byte, error) {
		calls++
		if timeout == 0 || timeout > 1000 {
			t.Fatalf("wait slice %d outside one second", timeout)
		}
		if calls < 3 {
			return nil, &Error{Op: "HcsWaitForComputeSystemExit", Code: 0x80070102}
		}
		return []byte(`{"Status":0,"ExitType":"GracefulExit"}`), nil
	})
	if err != nil || !status.Graceful() || calls != 3 {
		t.Fatalf("timeouts not retried: %+v %v %d", status, err, calls)
	}
	if _, err = waitExit(context.Background(), func(uintptr) ([]byte, error) { return []byte("not json"), nil }); err == nil {
		t.Fatal("invalid exit document accepted")
	}
	denied := &Error{Op: "HcsWaitForComputeSystemExit", Code: 0x80070005}
	if _, err = waitExit(context.Background(), func(uintptr) ([]byte, error) { return nil, denied }); !errors.Is(err, denied) {
		t.Fatal("terminal wait error retried", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = waitExit(ctx, func(uintptr) ([]byte, error) {
		time.Sleep(20 * time.Millisecond)
		return nil, &Error{Op: "HcsWaitForComputeSystemExit", Code: uint32(windows.HCS_E_OPERATION_TIMEOUT)}
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("wait ignored its deadline", err)
	}
}

// Resolving exports calls no HCS function. Hosts without Hyper-V lack the DLL.
func TestLoadResolvesExportsOrRefuses(t *testing.T) {
	if _, err := Load(); err != nil && !strings.HasPrefix(err.Error(), "required HCS export unavailable") {
		t.Fatal(err)
	}
}
