package diag

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRedactDirStreamsAndContinuesAfterErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("relies on POSIX permissions and symbolic links")
	}
	dir := t.TempDir()
	secret := "ghs_" + strings.Repeat("s", 36)
	// Sorted walk order: a-unreadable fails first; the files after it must
	// still be redacted.
	files := map[string]string{
		"a-unreadable.log": secret + "\n",
		"b/runner.log":     strings.Repeat("line without newline ", 8000) + secret,
		"c.log":            "token " + secret + "\n",
	}
	for name, data := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside.log")
	if err := os.WriteFile(outside, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "a-unreadable.log"), 0o200); err != nil {
		t.Fatal(err)
	}
	if err := RedactDir(dir); err == nil && os.Geteuid() != 0 {
		t.Fatal("unreadable file error hidden")
	}
	if _, err := os.Lstat(filepath.Join(dir, "a-unreadable.log")); !os.IsNotExist(err) {
		t.Fatal("unredactable file left on disk", err)
	}
	for _, name := range []string{"b/runner.log", "c.log"} {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil || strings.Contains(string(data), secret) || !strings.Contains(string(data), "<redacted>") {
			t.Fatalf("%s not redacted: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "link.log")); !os.IsNotExist(err) {
		t.Fatal("symbolic link kept", err)
	}
	if data, _ := os.ReadFile(outside); string(data) != secret {
		t.Fatal("redaction followed a symbolic link out of the directory")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".redact-") {
			t.Fatal("temporary file left behind")
		}
	}
}
