//go:build windows

package driverimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Cache, string, string, *int) {
	t.Helper()
	root := t.TempDir()
	baseDir := filepath.Join(root, "base")
	driverDir := filepath.Join(root, "display.inf_package")
	cacheDir := filepath.Join(root, "cache")
	for _, path := range []string{baseDir, driverDir, cacheDir} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(baseDir, "disk.vhdx")
	data := []byte("immutable prepared base")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	manifest, _ := json.Marshal(map[string]string{"output": source, "sha256": hex.EncodeToString(hash[:])})
	if err := os.WriteFile(filepath.Join(baseDir, "manifest.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(driverDir, "driver.dll"), []byte("driver-one"), 0600); err != nil {
		t.Fatal(err)
	}
	prepared := new(int)
	c := &Cache{root: cacheDir, bases: map[string]base{}, discover: func() ([]string, error) { return []string{driverDir}, nil }, check: noCheck, grant: noCheck,
		createDisk: func(child, _ string) error { return os.WriteFile(child, []byte("differencing-parent"), 0600) },
		prepare: func(_ context.Context, _ string, disk string, _ []string, packages []Package) error {
			*prepared++
			return os.WriteFile(disk, []byte(packages[0].Files[0].SHA256), 0600)
		}}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c, source, driverDir, prepared
}

func TestCacheReuseAndAutomaticDriverChange(t *testing.T) {
	c, source, driver, prepared := fixture(t)
	first, reused, err := c.Ensure(t.Context(), source)
	if err != nil || reused || *prepared != 1 {
		t.Fatal(first, reused, err)
	}
	second, reused, err := c.Ensure(t.Context(), source)
	if err != nil || !reused || first != second || *prepared != 1 {
		t.Fatal("cache hit prepared a new image", reused, err)
	}
	if err := os.WriteFile(filepath.Join(driver, "driver.dll"), []byte("driver-two"), 0600); err != nil {
		t.Fatal(err)
	}
	third, reused, err := c.Ensure(t.Context(), source)
	if err != nil || reused || first == third || *prepared != 2 {
		t.Fatal("driver change did not regenerate", reused, err)
	}
	if _, err := os.Stat(first); err != nil {
		t.Fatal("old generation was removed", err)
	}
	if _, _, err := c.Ensure(t.Context(), source); err != nil {
		t.Fatal(err)
	}
}

func TestCacheRefusesCorruptionAndRetainsFailedPreparation(t *testing.T) {
	c, source, _, prepared := fixture(t)
	path, _, err := c.Ensure(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Ensure(t.Context(), source); err == nil || *prepared != 1 {
		t.Fatal("corrupt generation reused or overwritten")
	}
	c2, source2, _, _ := fixture(t)
	c2.prepare = func(context.Context, string, string, []string, []Package) error {
		return errors.New("injected detach failure")
	}
	if _, _, err := c2.Ensure(t.Context(), source2); err == nil {
		t.Fatal("failed preparation published")
	}
	entries, err := os.ReadDir(c2.root)
	if err != nil || len(entries) != 1 {
		t.Fatal("failed workspace was not retained", err)
	}
	if filepath.Base(entries[0].Name())[:12] != "bivouac-gpu-" {
		t.Fatal("failure became a published key")
	}
}

func TestCacheRefusesHostDriverChangeDuringPreparation(t *testing.T) {
	c, source, driver, _ := fixture(t)
	previous := c.prepare
	c.prepare = func(ctx context.Context, workspace, disk string, paths []string, packages []Package) error {
		if err := previous(ctx, workspace, disk, paths, packages); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(driver, "driver.dll"), []byte("changed-mid-build"), 0600)
	}
	if _, _, err := c.Ensure(t.Context(), source); err == nil {
		t.Fatal("mixed driver generation published")
	}
}

func TestCacheRefusesInsufficientSpaceBeforeCreatingWorkspace(t *testing.T) {
	c, source, _, prepared := fixture(t)
	c.space = func(_ string, required int64) error {
		if required < 5<<30 {
			t.Fatal("missing free-space reserve")
		}
		return errors.New("injected space refusal")
	}
	if _, _, err := c.Ensure(t.Context(), source); err == nil || *prepared != 0 {
		t.Fatal("preparation bypassed the space guard")
	}
	entries, err := os.ReadDir(c.root)
	if err != nil || len(entries) != 0 {
		t.Fatal("space refusal created a workspace", err)
	}
}

func TestNativeDiscovery(t *testing.T) {
	if os.Getenv("BIVOUAC_GPU_INVENTORY_TEST") != "1" {
		t.Skip("opt-in read-only host inventory")
	}
	paths, err := Discover()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 || len(paths) > 8 {
		t.Fatal("invalid GPU package count")
	}
	t.Logf("discovered %d active GPU packages", len(paths))
}

func TestNativeCache(t *testing.T) {
	source, root := os.Getenv("BIVOUAC_GPU_IMAGE_TEST_BASE"), os.Getenv("BIVOUAC_GPU_IMAGE_TEST_ROOT")
	if source == "" || root == "" {
		t.Skip("opt-in administrator-protected image-cache lab")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	c, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	}()
	first, reused, err := c.Ensure(ctx, source)
	if err != nil || reused {
		t.Fatal("cold generation failed", err)
	}
	second, reused, err := c.Ensure(ctx, source)
	if err != nil || !reused || first != second {
		t.Fatal("warm generation failed", err)
	}
	t.Log("native offline preparation and verified cache reuse passed")
}

func TestPreparationScriptParsesInStockPowerShell(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prepare.ps1")
	if err := os.WriteFile(path, []byte(prepareScript), 0600); err != nil {
		t.Fatal(err)
	}
	parser := filepath.Join(t.TempDir(), "parse.ps1")
	const script = `param([string]$Path);$tokens=$null;$errors=$null;$null=[System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors);if($errors.Count){exit 1}`
	if err := os.WriteFile(parser, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	// #nosec G702 -- Fixed system parser reads only test-owned source, without executing it.
	cmd := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", parser, path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		t.Fatal("stock parser rejected GPU preparation script", err)
	}
}
