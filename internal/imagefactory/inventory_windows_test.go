//go:build windows

package imagefactory

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestInspectMediaOnly(t *testing.T) {
	dir := t.TempDir()
	// Configuration paths must be canonical even when TEMP uses an 8.3 alias.
	short, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	long := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(short, &long[0], windows.MAX_LONG_PATH)
	if err != nil || n == 0 || n >= windows.MAX_LONG_PATH {
		t.Fatal("long temp path unavailable")
	}
	dir = windows.UTF16ToString(long[:n])
	b := syntheticUDF()
	path := filepath.Join(dir, "install.iso")
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	c := testConfig()
	c.ISO = path
	c.ISOSHA256 = hashBytes(b)
	var out bytes.Buffer
	if e := Inspect(t.Context(), c, nil, &out); e != nil {
		t.Fatal(e)
	}
	var got MediaInventory
	if json.Unmarshal(out.Bytes(), &got) != nil || got.Selected.Index != 1 || got.ISOSHA256 != c.ISOSHA256 {
		t.Fatal("invalid media report")
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 {
		t.Fatal("inspect created a workspace or disk")
	}
	c.ISOSHA256 = strings.Repeat("0", 64)
	out.Reset()
	if e := Inspect(t.Context(), c, nil, &out); e == nil || out.Len() != 0 {
		t.Fatal("unverified ISO reported")
	}
}
