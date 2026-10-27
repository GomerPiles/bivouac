//go:build windows

package guestagent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAdapterGuardSerializesLaunchAndReceive(t *testing.T) {
	directory := receiveDirectory(t)
	d, err := openGuestDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := d.lock()
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	guard := &guestFilesGuard{directory: d, lock: lock}
	closed := false
	defer func() {
		if !closed {
			_ = guard.Close()
		}
	}()
	payload := []byte("adapter fixture")
	if err := receive(t.Context(), directory, "bivouac-helper.exe", int64(len(payload)), hashText(payload), bytes.NewReader(payload)); err == nil {
		t.Fatal("delivery bypassed the adapter lock")
	}
	if err := os.WriteFile(filepath.Join(directory, "launched"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err = guard.Close()
	closed = true
	if err != nil {
		t.Fatal(err)
	}
	if err := receive(t.Context(), directory, "bivouac-helper.exe", int64(len(payload)), hashText(payload), bytes.NewReader(payload)); err == nil {
		t.Fatal("delivery bypassed the published launch marker")
	}
}
