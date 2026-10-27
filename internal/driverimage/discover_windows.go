//go:build windows

package driverimage

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Discover resolves the installed INF of each present physical display device.
// No configured DriverStore directory or vendor version is retained across calls.
func Discover() ([]string, error) {
	class, err := windows.GUIDFromString("{4d36e968-e325-11ce-bfc1-08002be10318}")
	if err != nil {
		return nil, err
	}
	devices, err := windows.SetupDiGetClassDevsEx(&class, "PCI", 0, windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return nil, errors.New("GPU device enumeration failed")
	}
	defer func() { _ = devices.Close() }()
	resolve := windows.NewLazySystemDLL("setupapi.dll").NewProc("SetupGetInfDriverStoreLocationW")
	if resolve.Find() != nil {
		return nil, errors.New("GPU package resolution unavailable")
	}
	var paths []string
	for i := 0; i < 32; i++ {
		device, e := devices.EnumDeviceInfo(i)
		if errors.Is(e, windows.ERROR_NO_MORE_ITEMS) {
			break
		}
		if e != nil {
			return nil, errors.New("GPU enumeration failed")
		}
		handle, e := devices.OpenDevRegKey(device, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_READ)
		if e != nil {
			return nil, errors.New("GPU driver registry unavailable")
		}
		key := registry.Key(handle)
		inf, _, e := key.GetStringValue("InfPath")
		_ = key.Close()
		if e != nil || len(inf) > 128 || filepath.Base(inf) != inf || !strings.EqualFold(filepath.Ext(inf), ".inf") {
			return nil, errors.New("GPU installed INF unavailable")
		}
		text, e := windows.UTF16PtrFromString(inf)
		if e != nil {
			return nil, errors.New("GPU INF invalid")
		}
		var output [260]uint16
		var required uint32
		// #nosec G103 -- Fixed MAX_PATH output and documented SetupAPI ABI.
		ok, _, _ := resolve.Call(uintptr(unsafe.Pointer(text)), 0, 0, uintptr(unsafe.Pointer(&output[0])), uintptr(len(output)), uintptr(unsafe.Pointer(&required)))
		if ok == 0 || required == 0 || required > uint32(len(output)) {
			return nil, errors.New("active GPU package cannot be resolved")
		}
		path := filepath.Dir(windows.UTF16ToString(output[:]))
		system, e := windows.GetSystemDirectory()
		if e != nil {
			return nil, e
		}
		if !strings.EqualFold(filepath.Dir(path), filepath.Join(system, "DriverStore", "FileRepository")) {
			return nil, errors.New("GPU package is outside the system store")
		}
		paths = append(paths, path)
	}
	if len(paths) == 0 || len(paths) > 8 {
		return nil, errors.New("no bounded physical GPU inventory")
	}
	sort.Strings(paths)
	return paths, nil
}
