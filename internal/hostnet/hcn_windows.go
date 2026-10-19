//go:build windows

package hostnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
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
// use CoTaskMemFree.
type hcnAPI struct{ network *windows.LazyDLL }

func newHCN() *hcnAPI {
	return &hcnAPI{network: windows.NewLazySystemDLL("computenetwork.dll")}
}
func (a *hcnAPI) proc(name string) *windows.LazyProc { return a.network.NewProc(name) }
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
	for i := 0; i < maxNativeResponse/2; i++ {
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
	r, _, _ := a.proc(name).Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&detail))) // #nosec G103 -- Synchronous documented HCN ABI with stack-backed GUID and out parameters.
	return handle, nativeResult(name, r, detail)
}
func (a *hcnAPI) close(kind string, handle uintptr) {
	if handle != 0 {
		_, _, _ = a.proc("HcnClose" + kind).Call(handle)
	}
}
func (a *hcnAPI) query(kind string, handle uintptr, out any) error {
	query, err := windows.UTF16PtrFromString(`{"SchemaVersion":{"Major":2,"Minor":0}}`)
	if err != nil {
		return err
	}
	var properties, detail *uint16
	name := "HcnQuery" + kind + "Properties"
	r, _, _ := a.proc(name).Call(handle, uintptr(unsafe.Pointer(query)), uintptr(unsafe.Pointer(&properties)), uintptr(unsafe.Pointer(&detail))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
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
		r, _, _ = a.proc(name).Call(parent, uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&detail))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	} else {
		r, _, _ = a.proc(name).Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&detail))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
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
	r, _, _ := a.proc(name).Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&detail))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
	return nativeResult(name, r, detail)
}
func (a *hcnAPI) enumerateNetworks() ([]string, error) {
	query, _ := windows.UTF16PtrFromString(`{"SchemaVersion":{"Major":2,"Minor":0}}`)
	var properties, detail *uint16
	r, _, _ := a.proc("HcnEnumerateNetworks").Call(uintptr(unsafe.Pointer(query)), uintptr(unsafe.Pointer(&properties)), uintptr(unsafe.Pointer(&detail))) // #nosec G103 -- Documented HCN/HCS ABI; synchronous native buffers use paired allocator-specific frees.
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

// check confirms every required export before any resource is created.
// Missing features are a preflight error, not a fallback.
func (a *hcnAPI) check() error {
	for _, name := range []string{"HcnOpenNetwork", "HcnCreateNetwork", "HcnQueryNetworkProperties", "HcnCloseNetwork", "HcnDeleteNetwork", "HcnEnumerateNetworks", "HcnOpenEndpoint", "HcnCreateEndpoint", "HcnQueryEndpointProperties", "HcnCloseEndpoint", "HcnDeleteEndpoint"} {
		if err := a.proc(name).Find(); err != nil {
			return fmt.Errorf("required native API unavailable: %s", name)
		}
	}
	return nil
}
