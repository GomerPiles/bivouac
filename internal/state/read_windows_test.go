package state

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsAtomicReplacementWithOpenReader(t *testing.T) {
	for _, shareDelete := range []bool{false, true} {
		t.Run(map[bool]string{false: "retains-on-sharing-error", true: "reader-keeps-old-snapshot"}[shareDelete], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := WriteAtomic(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			name, err := windows.UTF16PtrFromString(path)
			if err != nil {
				t.Fatal(err)
			}
			share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE)
			if shareDelete {
				share |= windows.FILE_SHARE_DELETE
			}
			h, err := windows.CreateFile(name, windows.GENERIC_READ, share, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = windows.CloseHandle(h) }()
			err = WriteAtomic(path, []byte("new"), 0o600)
			if shareDelete && err != nil {
				t.Fatal(err)
			}
			if !shareDelete && err == nil {
				t.Fatal("replacement ignored the reader's deletion lock")
			}
			want := []byte("old")
			if shareDelete {
				want = []byte("new")
			}
			got, err := ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("committed state: %q %v", got, err)
			}
			var buf [3]byte
			var n uint32
			if err := windows.ReadFile(h, buf[:], &n, nil); err != nil || n != 3 || string(buf[:]) != "old" {
				t.Fatalf("reader snapshot: %q %v", buf, err)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 {
				t.Fatalf("temporary file leaked: %d %v", len(entries), err)
			}
		})
	}
}
