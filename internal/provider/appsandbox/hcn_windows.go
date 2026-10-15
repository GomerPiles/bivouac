//go:build windows

package appsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type nativeHRESULT struct {
	Operation string
	Code      uint32
}

func (e *nativeHRESULT) Error() string { return fmt.Sprintf("%s HRESULT 0x%08x", e.Operation, e.Code) }
func nativeMissing(err error, code uint32) bool {
	var hr *nativeHRESULT
	return errors.As(err, &hr) && hr.Code == code
}

// hcnAPI uses the documented Windows API ABI. Error JSON is discarded before
// returning errors; it can include arbitrary native/guest metadata. HCN buffers
// use CoTaskMemFree; HCS operation results use LocalFree.
type hcnAPI struct{ network, compute *windows.LazyDLL }

func newHCN() *hcnAPI {
	return &hcnAPI{network: windows.NewLazySystemDLL("computenetwork.dll"), compute: windows.NewLazySystemDLL("computecore.dll")}
}
func (a *hcnAPI) proc(compute bool, name string) *windows.LazyProc {
	if compute {
		return a.compute.NewProc(name)
	}
	return a.network.NewProc(name)
}
func nativeResult(name string, result uintptr, errorRecord *uint16) error {
	if errorRecord != nil {
		windows.CoTaskMemFree(unsafe.Pointer(errorRecord)) // #nosec G103 -- HCN owns and allocates this error buffer with CoTaskMemAlloc.
	}
	// HRESULT is a 32-bit ABI result; mask the native register before conversion.
	code := uint32(result & 0xffffffff)
	if code&0x80000000 != 0 {
		return &nativeHRESULT{Operation: name, Code: code}
	}
	return nil
}
func nativeText(pointer *uint16) ([]byte, error) {
	if pointer == nil {
		return nil, errors.New("empty native properties")
	}
	chars := make([]uint16, 0, 1024)
	for i := 0; i < maxResponseBytes/2; i++ {
		char := *(*uint16)(unsafe.Add(unsafe.Pointer(pointer), uintptr(i)*2)) // #nosec G103 -- Read the API's NUL-terminated UTF-16 buffer, with a strict scan bound.
		if char == 0 {
			return []byte(windows.UTF16ToString(chars)), nil
		}
		chars = append(chars, char)
	}
	return nil, errors.New("native properties exceed bound")
}
func (a *hcnAPI) open(kind, id string) (uintptr, error) {
	guid, err := windows.GUIDFromString("{" + id + "}")
	if err != nil {
		return 0, errors.New("invalid native resource ID")
	}
	var handle uintptr
	var detail *uint16
	name := "HcnOpen" + kind
	r, _, _ := a.proc(false, name).Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&detail))) // #nosec G103 -- Synchronous documented HCN ABI with stack-backed GUID and out parameters.
	return handle, nativeResult(name, r, detail)
}
func (a *hcnAPI) close(kind string, handle uintptr) {
	if handle != 0 {
		_, _, _ = a.proc(false, "HcnClose"+kind).Call(handle)
	}
}
func (a *hcnAPI) query(kind string, handle uintptr, out any) error {
	query, err := windows.UTF16PtrFromString(`{"SchemaVersion":{"Major":2,"Minor":0}}`)
	if err != nil {
		return err
	}
	var properties, detail *uint16
	name := "HcnQuery" + kind + "Properties"
	r, _, _ := a.proc(false, name).Call(handle, uintptr(unsafe.Pointer(query)), uintptr(unsafe.Pointer(&properties)), uintptr(unsafe.Pointer(&detail))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	if properties != nil {
		defer windows.CoTaskMemFree(unsafe.Pointer(properties)) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	}
	if err = nativeResult(name, r, detail); err != nil {
		return err
	}
	data, err := nativeText(properties)
	if err != nil {
		return err
	}
	if json.Unmarshal(data, out) != nil {
		return errors.New("invalid native networking JSON")
	}
	return nil
}
func (a *hcnAPI) create(kind string, parent uintptr, id string, settings any) (uintptr, error) {
	guid, err := windows.GUIDFromString("{" + id + "}")
	if err != nil {
		return 0, err
	}
	data, err := json.Marshal(settings)
	if err != nil {
		return 0, err
	}
	text, err := windows.UTF16PtrFromString(string(data))
	if err != nil {
		return 0, err
	}
	var handle uintptr
	var detail *uint16
	name := "HcnCreate" + kind
	var r uintptr
	if kind == "Endpoint" {
		r, _, _ = a.proc(false, name).Call(parent, uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&detail))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	} else {
		r, _, _ = a.proc(false, name).Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&detail))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	}
	runtime.KeepAlive(guid)
	runtime.KeepAlive(text)
	return handle, nativeResult(name, r, detail)
}
func (a *hcnAPI) delete(kind, id string) error {
	guid, err := windows.GUIDFromString("{" + id + "}")
	if err != nil {
		return err
	}
	var detail *uint16
	name := "HcnDelete" + kind
	r, _, _ := a.proc(false, name).Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&detail))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	return nativeResult(name, r, detail)
}
func (a *hcnAPI) enumerateNetworks() ([]string, error) {
	query, _ := windows.UTF16PtrFromString(`{"SchemaVersion":{"Major":2,"Minor":0}}`)
	var properties, detail *uint16
	r, _, _ := a.proc(false, "HcnEnumerateNetworks").Call(uintptr(unsafe.Pointer(query)), uintptr(unsafe.Pointer(&properties)), uintptr(unsafe.Pointer(&detail))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	if properties != nil {
		defer windows.CoTaskMemFree(unsafe.Pointer(properties)) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	}
	if err := nativeResult("HcnEnumerateNetworks", r, detail); err != nil {
		return nil, err
	}
	data, err := nativeText(properties)
	if err != nil {
		return nil, err
	}
	var ids []string
	if json.Unmarshal(data, &ids) != nil || len(ids) > 1024 {
		return nil, errors.New("invalid bounded network inventory")
	}
	return ids, nil
}
func (a *hcnAPI) attach(ctx context.Context, vm string, n NetworkPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(vm)
	if err != nil {
		return err
	}
	var system uintptr
	r, _, _ := a.proc(true, "HcsOpenComputeSystem").Call(uintptr(unsafe.Pointer(name)), 0x10000000, uintptr(unsafe.Pointer(&system))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	if err = nativeResult("HcsOpenComputeSystem", r, nil); err != nil {
		return err
	}
	defer func() { _, _, _ = a.proc(true, "HcsCloseComputeSystem").Call(system) }()
	op, _, _ := a.proc(true, "HcsCreateOperation").Call(0, 0)
	if op == 0 {
		return errors.New("cannot allocate native HCS operation")
	}
	defer func() { _, _, _ = a.proc(true, "HcsCloseOperation").Call(op) }()
	settings := map[string]any{"ResourcePath": "VirtualMachine/Devices/NetworkAdapters/" + n.EndpointID, "RequestType": "Add", "Settings": map[string]string{"EndpointId": n.EndpointID, "InstanceId": n.EndpointID, "MacAddress": n.MAC}}
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	text, err := windows.UTF16PtrFromString(string(data))
	if err != nil {
		return err
	}
	r, _, _ = a.proc(true, "HcsModifyComputeSystem").Call(system, op, uintptr(unsafe.Pointer(text)), 0) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	if err = nativeResult("HcsModifyComputeSystem", r, nil); err != nil {
		return err
	}
	timeout := 30 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline))
	}
	if timeout <= 0 {
		return errors.Join(ErrOutcomeUnknown, ctx.Err())
	}
	var result *uint16
	r, _, _ = a.proc(true, "HcsWaitForOperationResult").Call(op, uintptr(max(timeout.Milliseconds(), 1)), uintptr(unsafe.Pointer(&result))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	if result != nil {
		_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(result)))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	}
	if err = nativeResult("HcsWaitForOperationResult", r, nil); err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	return nil
}

// Ensure the pinned system DLLs export every required function before any
// resource is created. Missing features are a preflight error, not a fallback.
func (a *hcnAPI) check() error {
	for _, name := range []string{"HcnOpenNetwork", "HcnCreateNetwork", "HcnQueryNetworkProperties", "HcnCloseNetwork", "HcnDeleteNetwork", "HcnEnumerateNetworks", "HcnOpenEndpoint", "HcnCreateEndpoint", "HcnQueryEndpointProperties", "HcnCloseEndpoint", "HcnDeleteEndpoint"} {
		if err := a.proc(false, name).Find(); err != nil {
			return fmt.Errorf("required native API unavailable: %s", name)
		}
	}
	for _, name := range []string{"HcsOpenComputeSystem", "HcsCloseComputeSystem", "HcsCreateOperation", "HcsCloseOperation", "HcsModifyComputeSystem", "HcsWaitForOperationResult"} {
		if err := a.proc(true, name).Find(); err != nil {
			return fmt.Errorf("required native API unavailable: %s", name)
		}
	}
	return nil
}
