//go:build windows

package winrunner

import (
	"os"
	"testing"
	"unsafe"
)

func TestGPUDescriptionABI(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) == 8 && (unsafe.Sizeof(gpuDescription{}) != 312 || unsafe.Offsetof(gpuDescription{}.Flags) != 304) {
		t.Fatal("DXGI adapter description ABI differs")
	}
}

func TestNativeHardwareD3D12(t *testing.T) {
	if os.Getenv("BIVOUAC_D3D12_TEST") != "1" {
		t.Skip("opt-in hardware device creation")
	}
	if err := hardwareD3D12(); err != nil {
		t.Fatal(err)
	}
}
