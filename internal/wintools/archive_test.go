package wintools

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func fixtureZIP(t *testing.T, names []string, symlink bool) (string, Recipe) {
	t.Helper()
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if symlink {
			header.SetMode(os.ModeSymlink | 0o777)
		}
		out, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := out.Write([]byte("fixture")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "tool.zip")
	if err := os.WriteFile(file, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data.Bytes())
	return file, Recipe{Bytes: int64(data.Len()), SHA256: hex.EncodeToString(hash[:])}
}

func TestExtractRejectsUnsafeEntriesBeforeWriting(t *testing.T) {
	for _, names := range [][]string{
		{"good.txt", "../escape"}, {"C:/absolute"}, {`dir\escape`}, {"/absolute"},
		{"CON.txt"}, {"dir/NUL"}, {"LPT1.log"}, {"trailing. "}, {"alternate:stream"},
		{"tool.exe", "TOOL.EXE"}, {"dir/./file"}, {"dir//file"}, {"unicode-\u00b2"},
	} {
		t.Run(names[len(names)-1], func(t *testing.T) {
			archive, recipe := fixtureZIP(t, names, false)
			root := t.TempDir()
			if Extract(archive, root, recipe) == nil {
				t.Fatal("unsafe archive accepted")
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatal("refused archive wrote files", err)
			}
		})
	}
	archive, recipe := fixtureZIP(t, []string{"link"}, true)
	if Extract(archive, t.TempDir(), recipe) == nil {
		t.Fatal("symlink accepted")
	}
}

func TestExtractPinAndFreshness(t *testing.T) {
	archive, recipe := fixtureZIP(t, []string{"tool/bin/tool.exe", "readme.txt"}, false)
	root := t.TempDir()
	bad := recipe
	bad.SHA256 = "incorrect"
	if Extract(archive, root, bad) == nil {
		t.Fatal("wrong pin accepted")
	}
	if err := Extract(archive, root, recipe); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "tool", "bin", "tool.exe"))
	if err != nil || string(data) != "fixture" {
		t.Fatal("nested extraction incomplete", err)
	}
	if Extract(archive, root, recipe) == nil {
		t.Fatal("existing destination reused")
	}
}

func TestCatalogAndCorruptCacheRefuseWithoutDownload(t *testing.T) {
	for _, names := range [][]string{{"../cmake"}, {"cmake", "cmake"}, {"msvc"}, {"ninja", "unreviewed"}} {
		if _, err := Resolve(names); err == nil {
			t.Fatal("unsupported selection accepted", names)
		}
	}
	recipes, err := Resolve([]string{"ninja", "cmake"})
	if err != nil || len(recipes) != 2 || recipes[0].Name != "cmake" {
		t.Fatal("dependency order unavailable", err)
	}
	root := t.TempDir()
	name := filepath.Join(root, recipes[0].SHA256+".zip")
	if os.WriteFile(name, []byte("corrupt"), 0o600) != nil {
		t.Fatal("cache fixture failed")
	}
	if _, _, err := Acquire(context.Background(), root, recipes[0]); err == nil {
		t.Fatal("corrupt cache accepted")
	}
	data, err := os.ReadFile(name)
	if err != nil || string(data) != "corrupt" {
		t.Fatal("corrupt existing entry overwritten", err)
	}
	changed := recipes[0]
	changed.URL = "https://example.invalid/tool.zip"
	if _, _, err := Acquire(context.Background(), root, changed); err == nil {
		t.Fatal("unreviewed recipe accepted")
	}
}

func TestReleaseRedirects(t *testing.T) {
	for _, raw := range []string{"http://github.com/asset", "https://github.com.evil.invalid/asset", "https://user@github.com/asset", "https://github.com:8443/asset", "file:///asset"} {
		u, err := url.Parse(raw)
		if err != nil || releaseURL(u) {
			t.Fatal("unsafe release redirect", raw)
		}
	}
	u, err := url.Parse("https://release-assets.githubusercontent.com/asset?signature=public-fixture")
	if err != nil || !releaseURL(u) {
		t.Fatal("official delivery refused")
	}
}

func TestCLIExtractionRetainsLicensesAndBuildFiles(t *testing.T) {
	archive, recipe := fixtureZIP(t, []string{"bin/cmake.exe", "bin/cmake-gui.exe", "doc/cmake/html/help.html", "doc/cmake/LICENSE.rst", "share/Modules/FindPackage.cmake"}, false)
	recipe.OmitPrefix, recipe.OmitFile = "doc/cmake/html/", "bin/cmake-gui.exe"
	root := t.TempDir()
	if err := Extract(archive, root, recipe); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bin/cmake.exe", "doc/cmake/LICENSE.rst", "share/Modules/FindPackage.cmake"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(name))); err != nil {
			t.Fatal("required file omitted", name, err)
		}
	}
	for _, name := range []string{"doc/cmake/html", "bin/cmake-gui.exe"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(name))); !os.IsNotExist(err) {
			t.Fatal("unneeded file retained", name, err)
		}
	}
}
