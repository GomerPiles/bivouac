//go:build windows

package hcsspike

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestNativeErrorClassificationDoesNotExposeDocuments(t *testing.T) {
	for _, code := range []uint32{uint32(windows.HCS_E_OPERATION_TIMEOUT), uint32(windows.HCS_E_OPERATION_PENDING)} {
		err := hresult("create", uintptr(code))
		if err == nil || !unknownOperation(err) {
			t.Fatal("pending native create treated as settled")
		}
		if !strings.HasPrefix(err.Error(), "create HRESULT 0x") {
			t.Fatal("unexpected native error format")
		}
	}
	if !unknownOperation(context.Canceled) || !unknownOperation(context.DeadlineExceeded) {
		t.Fatal("canceled wait treated as settled")
	}
	if unknownOperation(hresult("create", uintptr(0x80070005))) || unknownOperation(nil) {
		t.Fatal("terminal result treated as pending")
	}
	if hresult("create", 0) != nil {
		t.Fatal("successful HRESULT rejected")
	}
}

func TestNativeOperationBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := operationTimeout(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled operation admitted")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	bound, err := operationTimeout(ctx)
	if err != nil || bound == 0 || bound > 100 {
		t.Fatalf("deadline not clipped: %d %v", bound, err)
	}
}

func TestBoundedNativeUTF16Result(t *testing.T) {
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
}

func TestPayloadProofDetectsFileReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(path, []byte("owned"), 0600); err != nil {
		t.Fatal(err)
	}
	proof, err := capturePayload(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = proof.verify(); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = proof.verify(); err == nil {
		t.Fatal("replaced payload accepted")
	}
}

func TestPayloadProofDetectsACLChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(path, []byte("owned"), 0600); err != nil {
		t.Fatal(err)
	}
	proof, err := capturePayload(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;OW)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err = proof.verify(); err == nil {
		t.Fatal("changed payload permissions accepted")
	}
}

func TestLifecycleOperationsUseNullOptions(t *testing.T) {
	for _, method := range []string{"HcsStartComputeSystem", "HcsTerminateComputeSystem"} {
		p, err := operationInput(method, "")
		if err != nil || p != nil {
			t.Fatal("reserved lifecycle options must be a native NULL")
		}
		if _, err = operationInput(method, "{}"); err == nil {
			t.Fatal("reserved lifecycle JSON accepted")
		}
	}
	for _, method := range []string{"HcsGetComputeSystemProperties", "HcsModifyComputeSystem"} {
		p, err := operationInput(method, "{}")
		if err != nil || p == nil {
			t.Fatal("required HCS document missing")
		}
	}
}

func TestBasicPropertyQueryUsesSchemaDefault(t *testing.T) {
	p, err := operationInput("HcsGetComputeSystemProperties", basicPropertyQuery())
	if err != nil || p == nil {
		t.Fatal("default query missing")
	}
	var query map[string]json.RawMessage
	if err := json.Unmarshal([]byte(windows.UTF16PtrToString(p)), &query); err != nil {
		t.Fatal(err)
	}
	if len(query) != 0 {
		t.Fatal("basic identity must use default properties, without an invalid selector")
	}
}

func TestDriverCopyRequiresExactObservedSize(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size      int64
		wantError bool
	}{{"exact", 7, false}, {"short", 8, true}, {"grew", 6, true}, {"empty", 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			source := t.TempDir()
			if err := os.WriteFile(filepath.Join(source, "private-driver-name"), []byte("payload"), 0600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(source)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			destination := filepath.Join(t.TempDir(), "copy")
			err = copyDriverFile(root, "private-driver-name", destination, tc.size)
			if (err != nil) != tc.wantError {
				t.Fatalf("size gate mismatch: %v", err)
			}
			if err != nil && (strings.Contains(err.Error(), source) || strings.Contains(err.Error(), "private-driver-name")) {
				t.Fatal("copy diagnostic exposed a source identity")
			}
			if err == nil {
				b, e := os.ReadFile(destination)
				if e != nil || string(b) != "payload" {
					t.Fatal("successful copy differs")
				}
			}
		})
	}
}

func TestImageExitRequiresNativeGracefulSuccess(t *testing.T) {
	for _, data := range []string{`{}`, `{"ExitType":"ForcedExit"}`, `{"ExitType":"UnexpectedExit"}`, `{"ExitType":"Unknown"}`, `{"ExitType":"GracefulExit","Status":-1}`, `{"ExitType":"GracefulExit"} trailing`} {
		if validateGracefulExit([]byte(data)) == nil {
			t.Fatal("ambiguous/unclean exit accepted", data)
		}
	}
	for _, data := range []string{`{"ExitType":"GracefulExit"}`, `{"ExitType":"GracefulExit","Status":0}`} {
		if err := validateGracefulExit([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
}
func TestImageExitWaitCancellationAndErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := waitGracefulExit(ctx, func(timeout uintptr) ([]byte, error) {
		calls++
		if timeout > 1000 {
			t.Fatal("unbounded exit poll")
		}
		cancel()
		return nil, hresult("wait", 0x80070102)
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("cancellation ignored", err, calls)
	}
	calls = 0
	if waitGracefulExit(context.Background(), func(uintptr) ([]byte, error) { calls++; return nil, hresult("wait", 0x80070005) }) == nil || calls != 1 {
		t.Fatal("terminal native wait retried")
	}
}
