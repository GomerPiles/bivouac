// Package wintools describes reviewed Windows tool payloads. Acquisition never
// executes them; installation and functional verification belong to the guest.
package wintools

import (
	"errors"
	"slices"
)

type Recipe struct {
	Variant, OmitPrefix, OmitFile       string
	Name, Version, URL, SHA256, License string
	VersionOutput                       string
	Bytes                               int64
	Executable                          string
}

// Resolve returns fresh values, in installation order, without consulting a
// mutable external catalog or resolving latest versions. Digests are the
// sha256 asset digests published by the corresponding official GitHub releases.
func Resolve(names []string) ([]Recipe, error) {
	catalog := []Recipe{
		{Name: "pwsh", Version: "7.6.9", URL: "https://github.com/PowerShell/PowerShell/releases/download/v7.6.9/PowerShell-7.6.9-win-x64.zip", SHA256: "ce7484804c0f0ad4dda10c958e71acdaf7eebfb22505c1b480f89e0e9f1da94d", License: "MIT", Bytes: 109620855, Executable: "pwsh.exe", VersionOutput: "PowerShell 7.6.9"},
		{Name: "git", Version: "2.56.0.windows.4", URL: "https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.4/MinGit-2.56.0.4-64-bit.zip", SHA256: "e3bf78351fe777fba47ddee5950082f8a98bb0f02604fdc7ba3ee2cb68ffa877", License: "GPL-2.0", Bytes: 39846926, Executable: "cmd/git.exe", VersionOutput: "git version 2.56.0.windows.4"},
		{Name: "cmake", Version: "4.4.4", URL: "https://github.com/Kitware/CMake/releases/download/v4.4.4/cmake-4.4.4-windows-x86_64.zip", SHA256: "bace36e94b31c68ab6fa295f26dfa11219e0701cf7c94b0284a7d1cb13dac536", License: "BSD-3-Clause", Bytes: 54400562, Executable: "cmake-4.4.4-windows-x86_64/bin/cmake.exe", VersionOutput: "cmake version 4.4.4", Variant: "cli", OmitPrefix: "cmake-4.4.4-windows-x86_64/doc/cmake/html/", OmitFile: "cmake-4.4.4-windows-x86_64/bin/cmake-gui.exe"},
		{Name: "ninja", Version: "1.13.2", URL: "https://github.com/ninja-build/ninja/releases/download/v1.13.2/ninja-win.zip", SHA256: "07fc8261b42b20e71d1720b39068c2e14ffcee6396b76fb7a795fb460b78dc65", License: "Apache-2.0", Bytes: 291570, Executable: "ninja.exe", VersionOutput: "1.13.2"},
	}
	if len(names) > len(catalog) {
		return nil, errors.New("tool selection exceeds catalog bound")
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] || !slices.ContainsFunc(catalog, func(r Recipe) bool { return r.Name == name }) {
			return nil, errors.New("unknown or duplicate Windows tool")
		}
		seen[name] = true
	}
	result := []Recipe{}
	for _, recipe := range catalog {
		if seen[recipe.Name] {
			result = append(result, recipe)
		}
	}
	return result, nil
}
