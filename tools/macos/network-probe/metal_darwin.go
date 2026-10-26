package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

// metal submits and verifies a real GPU buffer copy in the disposable Aqua
// session. It does not stand in for window rendering, focus or input tests.
func metal() error {
	if _, err := purego.Dlopen("/System/Library/Frameworks/Foundation.framework/Foundation", purego.RTLD_NOW|purego.RTLD_GLOBAL); err != nil {
		return errors.New("guest Foundation unavailable")
	}
	lib, err := purego.Dlopen("/System/Library/Frameworks/Metal.framework/Metal", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return errors.New("guest Metal unavailable")
	}
	symbol, err := purego.Dlsym(lib, "MTLCreateSystemDefaultDevice")
	if err != nil {
		return errors.New("guest Metal device factory unavailable")
	}
	var create func() objc.ID
	purego.RegisterFunc(&create, symbol)
	pool := objc.ID(objc.GetClass("NSAutoreleasePool")).Send(objc.RegisterName("new"))
	defer pool.Send(objc.RegisterName("drain"))
	device := create()
	if device == 0 {
		return errors.New("guest Metal device absent")
	}
	defer device.Send(objc.RegisterName("release"))
	queue := device.Send(objc.RegisterName("newCommandQueue"))
	if queue == 0 {
		return errors.New("guest GPU queue unavailable")
	}
	defer queue.Send(objc.RegisterName("release"))
	source := device.Send(objc.RegisterName("newBufferWithLength:options:"), uint64(16), uint64(0))
	if source == 0 {
		return errors.New("guest GPU buffers unavailable")
	}
	defer source.Send(objc.RegisterName("release"))
	destination := device.Send(objc.RegisterName("newBufferWithLength:options:"), uint64(16), uint64(0))
	if destination == 0 {
		return errors.New("guest GPU buffers unavailable")
	}
	defer destination.Send(objc.RegisterName("release"))
	a := objc.Send[unsafe.Pointer](source, objc.RegisterName("contents"))
	b := objc.Send[unsafe.Pointer](destination, objc.RegisterName("contents"))
	if a == nil || b == nil {
		return errors.New("guest shared GPU buffers unavailable")
	}
	from := unsafe.Slice((*byte)(a), 16) //nolint:gosec // Metal owns the checked 16-byte shared buffer until deferred release.
	to := unsafe.Slice((*byte)(b), 16)   //nolint:gosec // Metal owns the checked 16-byte shared buffer until deferred release.
	for i := range from {
		from[i] = byte(i + 1)
	}
	clear(to)
	command := queue.Send(objc.RegisterName("commandBuffer"))
	if command == 0 {
		return errors.New("guest GPU command buffer unavailable")
	}
	blit := command.Send(objc.RegisterName("blitCommandEncoder"))
	if blit == 0 {
		return errors.New("guest GPU encoder unavailable")
	}
	blit.Send(objc.RegisterName("copyFromBuffer:sourceOffset:toBuffer:destinationOffset:size:"), source, uint64(0), destination, uint64(0), uint64(16))
	blit.Send(objc.RegisterName("endEncoding"))
	command.Send(objc.RegisterName("commit"))
	command.Send(objc.RegisterName("waitUntilCompleted"))
	if command.Send(objc.RegisterName("status")) != 4 || !bytes.Equal(from, to) {
		return errors.New("guest GPU copy verification failed")
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Metal bool `json:"metal_copy_verified"`
	}{true})
}
