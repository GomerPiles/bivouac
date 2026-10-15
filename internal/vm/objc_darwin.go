package vm

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

// framework holds the Foundation, Virtualization and libdispatch bindings of
// one helper process. Purego calls them without cgo; the process needs the
// com.apple.security.virtualization entitlement.
type framework struct {
	queueCreate  func(label string, attr uintptr) uintptr
	syncF        func(queue, context, work uintptr)
	poolPush     func() uintptr
	poolPop      func(uintptr)
	callback     uintptr
	mu           sync.Mutex
	nextWork     uintptr
	pendingWork  map[uintptr]func()
	selectorLock sync.Mutex
	selectors    map[string]objc.SEL
}

func openFramework() (*framework, error) {
	for _, path := range []string{
		"/System/Library/Frameworks/Foundation.framework/Foundation",
		"/System/Library/Frameworks/Virtualization.framework/Virtualization",
	} {
		if _, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL); err != nil {
			return nil, fmt.Errorf("load %s: %w", path, err)
		}
	}
	system, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, errors.New("load libSystem")
	}
	runtime, err := purego.Dlopen("/usr/lib/libobjc.A.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, errors.New("load libobjc")
	}
	f := &framework{pendingWork: map[uintptr]func(){}, selectors: map[string]objc.SEL{}}
	for _, binding := range []struct {
		lib      uintptr
		name     string
		function any
	}{
		{system, "dispatch_queue_create", &f.queueCreate}, {system, "dispatch_sync_f", &f.syncF},
		{runtime, "objc_autoreleasePoolPush", &f.poolPush}, {runtime, "objc_autoreleasePoolPop", &f.poolPop},
	} {
		address, err := purego.Dlsym(binding.lib, binding.name)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", binding.name, err)
		}
		purego.RegisterFunc(binding.function, address)
	}
	// One trampoline per process: purego never frees callbacks.
	f.callback = purego.NewCallback(func(context uintptr) uintptr {
		f.mu.Lock()
		work := f.pendingWork[context]
		delete(f.pendingWork, context)
		f.mu.Unlock()
		if work != nil {
			work()
		}
		return 0
	})
	return f, nil
}

// onQueue runs work synchronously on a dispatch queue inside an autorelease
// pool. Virtualization requires every machine call on the machine's queue.
func (f *framework) onQueue(queue uintptr, work func()) {
	f.mu.Lock()
	f.nextWork++
	key := f.nextWork
	f.pendingWork[key] = func() {
		pool := f.poolPush()
		defer f.poolPop(pool)
		work()
	}
	f.mu.Unlock()
	f.syncF(queue, key, f.callback)
}

func (f *framework) sel(name string) objc.SEL {
	f.selectorLock.Lock()
	defer f.selectorLock.Unlock()
	s, ok := f.selectors[name]
	if !ok {
		s = objc.RegisterName(name)
		f.selectors[name] = s
	}
	return s
}

// class returns a class object, or 0 when this macOS lacks it.
func (f *framework) class(name string) objc.ID { return objc.ID(objc.GetClass(name)) }

func (f *framework) send(id objc.ID, selector string, args ...any) objc.ID {
	return id.Send(f.sel(selector), args...)
}

// make is [[Class alloc] init...] or [Class new]: a retained object owned by
// the configuration that receives it.
func (f *framework) make(class string, init string, args ...any) (objc.ID, error) {
	c := f.class(class)
	if c == 0 {
		return 0, fmt.Errorf("%s is unavailable on this macOS", class)
	}
	if init == "" {
		return f.send(c, "new"), nil
	}
	id := f.send(f.send(c, "alloc"), init, args...)
	if id == 0 {
		return 0, fmt.Errorf("%s %s failed", class, init)
	}
	return id, nil
}

// makeErr is make for initializers whose last argument is NSError **.
func (f *framework) makeErr(class string, init string, args ...any) (objc.ID, error) {
	c := f.class(class)
	if c == 0 {
		return 0, fmt.Errorf("%s is unavailable on this macOS", class)
	}
	var nsErr objc.ID
	id := f.send(f.send(c, "alloc"), init, append(args, errOut(&nsErr))...)
	if id == 0 {
		return 0, fmt.Errorf("%s: %s", class, f.errorText(nsErr))
	}
	return id, nil
}

// errOut passes an NSError ** out-parameter, valid for one call.
func errOut(e *objc.ID) unsafe.Pointer {
	return unsafe.Pointer(e) //nolint:gosec // Objective-C writes one pointer during the call.
}

func (f *framework) str(s string) objc.ID {
	return f.send(f.class("NSString"), "stringWithUTF8String:", s)
}

func (f *framework) goString(s objc.ID) string {
	if s == 0 {
		return ""
	}
	return objc.Send[string](s, f.sel("UTF8String"))
}

func (f *framework) url(path string) objc.ID {
	return f.send(f.class("NSURL"), "fileURLWithPath:", f.str(path))
}

func (f *framework) data(b []byte) objc.ID {
	if len(b) == 0 {
		return f.send(f.class("NSData"), "data")
	}
	return f.send(f.class("NSData"), "dataWithBytes:length:", unsafe.Pointer(&b[0]), uint64(len(b))) //nolint:gosec // Copied during the call.
}

func (f *framework) array(items ...objc.ID) objc.ID {
	if len(items) == 0 {
		return f.send(f.class("NSArray"), "array")
	}
	return f.send(f.class("NSArray"), "arrayWithObjects:count:", unsafe.Pointer(&items[0]), uint64(len(items))) //nolint:gosec // Copied during the call.
}

func (f *framework) errorText(nsErr objc.ID) string {
	if nsErr == 0 {
		return "unknown error"
	}
	return f.goString(f.send(nsErr, "localizedDescription"))
}
