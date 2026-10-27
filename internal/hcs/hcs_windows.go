//go:build windows

package hcs

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

// defaultWait bounds a native wait when the caller's context has no deadline.
const defaultWait = 2 * time.Minute

// API holds computecore.dll exports resolved by Load. It has no other state;
// callers own each System it returns.
type API struct {
	createOperation, closeOperation, waitOperation            *windows.LazyProc
	create, open, closeSystem, properties, start, terminate   *windows.LazyProc
	modify, waitExit, grantVMAccess, guestState, runtimeState *windows.LazyProc
}

// Load resolves every export bivouac uses, so a host lacking Hyper-V or any
// required call fails before a VM is planned. It calls no HCS function.
func Load() (*API, error) {
	if runtime.GOARCH != "amd64" {
		return nil, errors.New("HCS guests require Windows amd64")
	}
	dll := windows.NewLazySystemDLL("computecore.dll")
	a := &API{
		createOperation: dll.NewProc("HcsCreateOperation"),
		closeOperation:  dll.NewProc("HcsCloseOperation"),
		waitOperation:   dll.NewProc("HcsWaitForOperationResult"),
		create:          dll.NewProc("HcsCreateComputeSystem"),
		open:            dll.NewProc("HcsOpenComputeSystem"),
		closeSystem:     dll.NewProc("HcsCloseComputeSystem"),
		properties:      dll.NewProc("HcsGetComputeSystemProperties"),
		start:           dll.NewProc("HcsStartComputeSystem"),
		terminate:       dll.NewProc("HcsTerminateComputeSystem"),
		modify:          dll.NewProc("HcsModifyComputeSystem"),
		waitExit:        dll.NewProc("HcsWaitForComputeSystemExit"),
		grantVMAccess:   dll.NewProc("HcsGrantVmAccess"),
		guestState:      dll.NewProc("HcsCreateEmptyGuestStateFile"),
		runtimeState:    dll.NewProc("HcsCreateEmptyRuntimeStateFile"),
	}
	for _, p := range []*windows.LazyProc{a.createOperation, a.closeOperation, a.waitOperation, a.create, a.open, a.closeSystem, a.properties, a.start, a.terminate, a.modify, a.waitExit, a.grantVMAccess, a.guestState, a.runtimeState} {
		if err := p.Find(); err != nil {
			return nil, fmt.Errorf("required HCS export unavailable: %s", p.Name)
		}
	}
	return a, nil
}

// Error is a failed HCS call reduced to its operation and HRESULT. HCS error
// documents can name host paths and are never retained.
type Error struct {
	Op   string
	Code uint32
}

func (e *Error) Error() string { return fmt.Sprintf("%s HRESULT 0x%08x", e.Op, e.Code) }

// ErrNotFound reports that no compute system has the requested name.
var ErrNotFound = errors.New("compute system not found")

// OutcomeUnknown reports an error after which a dispatched mutation may still
// complete. Callers must not replay the mutation; only a later native
// observation of the exact instance settles it.
func OutcomeUnknown(err error) bool {
	var e *Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		(errors.As(err, &e) && (e.Code == uint32(windows.HCS_E_OPERATION_TIMEOUT) || e.Code == uint32(windows.HCS_E_OPERATION_PENDING)))
}

func hresult(op string, r uintptr) error {
	code := uint32(r & 0xffffffff)
	if code&0x80000000 != 0 {
		return &Error{Op: op, Code: code}
	}
	return nil
}

// waitBound converts the caller's remaining deadline to native milliseconds.
func waitBound(ctx context.Context) (uintptr, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	bound := defaultWait
	if deadline, ok := ctx.Deadline(); ok {
		bound = time.Until(deadline)
	}
	if bound <= 0 {
		return 0, context.DeadlineExceeded
	}
	return uintptr(max(1, bound.Milliseconds())), nil
}

// boundedResult copies an HCS-allocated, NUL-terminated UTF-16 result of at
// most 64 KiB.
func boundedResult(p *uint16) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	words := make([]uint16, 0, 1024)
	for i := 0; i < 32768; i++ {
		word := *(*uint16)(unsafe.Add(unsafe.Pointer(p), i*2)) // #nosec G103 -- HCS returns a NUL-terminated UTF-16 allocation; inspect at most 64 KiB and stop at its terminator.
		if word == 0 {
			return []byte(windows.UTF16ToString(words)), nil
		}
		words = append(words, word)
	}
	return nil, errors.New("HCS result exceeds 64 KiB")
}

func freeResult(p *uint16) {
	if p != nil {
		_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(p)))) // #nosec G103 -- HCS results are LocalAlloc allocations owned by the caller.
	}
}

// operation dispatches one asynchronous HCS call and waits for its result
// within the context's deadline. The wait is not interrupted by cancellation
// before that deadline; a timed-out operation is OutcomeUnknown.
func (a *API) operation(ctx context.Context, op string, dispatch func(op uintptr) uintptr) ([]byte, error) {
	bound, err := waitBound(ctx)
	if err != nil {
		return nil, err
	}
	handle, _, _ := a.createOperation.Call(0, 0)
	if handle == 0 {
		return nil, errors.New("cannot allocate HCS operation")
	}
	defer func() { _, _, _ = a.closeOperation.Call(handle) }()
	if err = hresult(op, dispatch(handle)); err != nil {
		return nil, err
	}
	var result *uint16
	r, _, _ := a.waitOperation.Call(handle, bound, uintptr(unsafe.Pointer(&result))) // #nosec G103 -- Documented HCS ABI; the result allocation is released below, including failure documents.
	defer freeResult(result)
	if err = hresult(op, r); err != nil {
		return nil, err
	}
	return boundedResult(result)
}

// System is one open compute system handle, owned by its caller.
//
// Keep the handle that created or started a guest until its ownership has been
// verified and Terminate has completed. With TerminateOnLastHandleClosed,
// closing it first starts an asynchronous teardown during which property
// queries can fail, and absence cannot yet be confirmed.
type System struct {
	api    *API
	handle uintptr
}

// Create dispatches a new compute system. On any error the handle is closed;
// use OutcomeUnknown to learn whether the guest may still appear.
func (a *API) Create(ctx context.Context, id string, doc ComputeSystem) (*System, error) {
	name, err := windows.UTF16PtrFromString(id)
	if err != nil {
		return nil, errors.New("invalid compute system name")
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	text, err := windows.UTF16PtrFromString(string(b))
	if err != nil {
		return nil, err
	}
	var handle uintptr
	_, err = a.operation(ctx, "HcsCreateComputeSystem", func(op uintptr) uintptr {
		r, _, _ := a.create.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(text)), op, 0, uintptr(unsafe.Pointer(&handle))) // #nosec G103 -- Documented HCS create ABI with an owned output handle.
		return r
	})
	runtime.KeepAlive(name)
	runtime.KeepAlive(text)
	s := &System{api: a, handle: handle}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Open returns ErrNotFound when no compute system has this name.
func (a *API) Open(ctx context.Context, id string) (*System, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(id)
	if err != nil {
		return nil, errors.New("invalid compute system name")
	}
	const genericAll = 0x10000000
	var handle uintptr
	r, _, _ := a.open.Call(uintptr(unsafe.Pointer(name)), genericAll, uintptr(unsafe.Pointer(&handle))) // #nosec G103 -- HCS open ABI with an owned output handle.
	if uint32(r&0xffffffff) == uint32(windows.HCS_E_SYSTEM_NOT_FOUND) {
		return nil, ErrNotFound
	}
	if err = hresult("HcsOpenComputeSystem", r); err != nil {
		return nil, err
	}
	return &System{api: a, handle: handle}, nil
}

// EnumerateOwner reads basic properties for one fixed owner. It opens no VM
// handle and never exposes the native result/error document to diagnostics.
func (a *API) EnumerateOwner(ctx context.Context, owner string) ([]Properties, error) {
	if owner == "" || len(owner) > 64 {
		return nil, errors.New("HCS enumeration owner required")
	}
	data, err := json.Marshal(struct {
		Owners []string `json:"Owners"`
	}{[]string{owner}})
	if err != nil {
		return nil, errors.New("HCS enumeration query unavailable")
	}
	query, err := windows.UTF16PtrFromString(string(data))
	if err != nil {
		return nil, errors.New("HCS enumeration query invalid")
	}
	enumerate := windows.NewLazySystemDLL("computecore.dll").NewProc("HcsEnumerateComputeSystems")
	if enumerate.Find() != nil {
		return nil, errors.New("HCS enumeration unavailable")
	}
	data, err = a.operation(ctx, "HcsEnumerateComputeSystems", func(operation uintptr) uintptr {
		// #nosec G103 -- Fixed owner-filtered query and owned HCS operation.
		code, _, _ := enumerate.Call(uintptr(unsafe.Pointer(query)), operation)
		return code
	})
	if err != nil {
		return nil, err
	}
	var properties []Properties
	if json.Unmarshal(data, &properties) != nil || properties == nil || len(properties) > 64 {
		return nil, errors.New("HCS enumeration result refused")
	}
	return properties, nil
}

// Properties uses the schema's default query, which returns identity and
// state. "Basic" is a service property selector, not a compute-system query.
func (s *System) Properties(ctx context.Context) (Properties, error) {
	var p Properties
	query, err := windows.UTF16PtrFromString("{}")
	if err != nil {
		return p, err
	}
	b, err := s.api.operation(ctx, "HcsGetComputeSystemProperties", func(op uintptr) uintptr {
		r, _, _ := s.api.properties.Call(s.handle, op, uintptr(unsafe.Pointer(query))) // #nosec G103 -- HCS property query ABI.
		return r
	})
	runtime.KeepAlive(query)
	if err != nil {
		return p, err
	}
	if json.Unmarshal(b, &p) != nil {
		return p, errors.New("invalid compute system properties")
	}
	return p, nil
}

// Start and Terminate reserve their options argument: it must be NULL, not an
// empty JSON document or an empty string.
func (s *System) Start(ctx context.Context) error {
	_, err := s.api.operation(ctx, "HcsStartComputeSystem", func(op uintptr) uintptr {
		r, _, _ := s.api.start.Call(s.handle, op, 0)
		return r
	})
	return err
}

// Terminate completing is not proof of absence; confirm with Open.
func (s *System) Terminate(ctx context.Context) error {
	_, err := s.api.operation(ctx, "HcsTerminateComputeSystem", func(op uintptr) uintptr {
		r, _, _ := s.api.terminate.Call(s.handle, op, 0)
		return r
	})
	return err
}

func (s *System) Modify(ctx context.Context, request ModifyRequest) error {
	b, err := json.Marshal(request)
	if err != nil {
		return err
	}
	text, err := windows.UTF16PtrFromString(string(b))
	if err != nil {
		return err
	}
	_, err = s.api.operation(ctx, "HcsModifyComputeSystem", func(op uintptr) uintptr {
		r, _, _ := s.api.modify.Call(s.handle, op, uintptr(unsafe.Pointer(text)), 0) // #nosec G103 -- HCS modify ABI; the identity argument is unused.
		return r
	})
	runtime.KeepAlive(text)
	return err
}

// WaitExit waits on this handle for the guest to exit, in one-second native
// slices so that cancellation is observed promptly. Absence is not an exit.
func (s *System) WaitExit(ctx context.Context) (ExitStatus, error) {
	return waitExit(ctx, func(timeout uintptr) ([]byte, error) {
		var result *uint16
		r, _, _ := s.api.waitExit.Call(s.handle, timeout, uintptr(unsafe.Pointer(&result))) // #nosec G103 -- Documented HCS wait ABI; the result allocation is released below.
		defer freeResult(result)
		if err := hresult("HcsWaitForComputeSystemExit", r); err != nil {
			return nil, err
		}
		return boundedResult(result)
	})
}

func waitExit(ctx context.Context, wait func(uintptr) ([]byte, error)) (ExitStatus, error) {
	const waitTimeout, errorTimeout = 0x80070102, 0x800705b4
	for {
		bound, err := waitBound(ctx)
		if err != nil {
			return ExitStatus{}, err
		}
		data, err := wait(min(bound, 1000))
		if err != nil {
			var e *Error
			if errors.As(err, &e) && (e.Code == uint32(windows.HCS_E_OPERATION_TIMEOUT) || e.Code == waitTimeout || e.Code == errorTimeout) {
				continue
			}
			return ExitStatus{}, err
		}
		var status ExitStatus
		if json.Unmarshal(data, &status) != nil {
			return ExitStatus{}, errors.New("invalid compute system exit status")
		}
		return status, nil
	}
}

func (s *System) Close() {
	if s.handle != 0 {
		_, _, _ = s.api.closeSystem.Call(s.handle)
		s.handle = 0
	}
}

// GrantVMAccess adds the named guest's VM account to one file's ACL. Grant
// each file a guest needs, not just its directory: existing descendants are
// not guaranteed to inherit the grant.
func (a *API) GrantVMAccess(id, path string) error {
	name, err := windows.UTF16PtrFromString(id)
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, _ := a.grantVMAccess.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(file))) // #nosec G103 -- HCS grant ABI on a caller-owned file.
	return hresult("HcsGrantVmAccess", r)
}

// CreateGuestStateFiles creates the fresh, empty firmware/TPM and runtime
// state files a new guest needs. Each guest gets its own; none are reused.
func (a *API) CreateGuestStateFiles(guestState, runtimeState string) error {
	for _, item := range []struct {
		op   string
		proc *windows.LazyProc
		path string
	}{{"HcsCreateEmptyGuestStateFile", a.guestState, guestState}, {"HcsCreateEmptyRuntimeStateFile", a.runtimeState, runtimeState}} {
		p, err := windows.UTF16PtrFromString(item.path)
		if err != nil {
			return err
		}
		r, _, _ := item.proc.Call(uintptr(unsafe.Pointer(p))) // #nosec G103 -- HCS state-file ABI on a new caller-owned path.
		if err = hresult(item.op, r); err != nil {
			return err
		}
	}
	return nil
}
