//go:build windows

package imagefactory

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyPinnedHashesWrittenBytes(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "input.bin")
	dest := filepath.Join(dir, "owned-copy.bin")
	payload := bytes.Repeat([]byte("public pinned input\n"), 100000)
	if e := os.WriteFile(source, payload, 0600); e != nil {
		t.Fatal(e)
	}
	expected := hashBytes(payload)
	n, digest, e := copyPinned(t.Context(), source, dest, expected, int64(len(payload)))
	copied, readErr := os.ReadFile(dest)
	if e != nil || readErr != nil || n != int64(len(payload)) || digest != expected || hashBytes(copied) != digest || !bytes.Equal(copied, payload) {
		t.Fatal("copied bytes differ from one-pass digest")
	}
	if _, _, e = copyPinned(t.Context(), source, filepath.Join(dir, "rejected-copy.bin"), strings.Repeat("0", 64), int64(len(payload))); e == nil {
		t.Fatal("wrong input pin accepted")
	}
}

func TestMediaCopySpaceBeforeInventory(t *testing.T) {
	required, e := requiredMediaCopySpace(123)
	if e != nil || required != 123+(10<<30) {
		t.Fatal("copy-only admission includes invented image bytes")
	}
	for _, size := range []uint64{0, (32 << 30) + 1} {
		if _, e := requiredMediaCopySpace(size); e == nil {
			t.Fatal("unbounded ISO copy admitted")
		}
	}
}
