//go:build windows

package hcsspike

import (
	"context"
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
