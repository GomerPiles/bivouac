//go:build windows

package vmhost

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/guestagent"
)

func TestProtectedImageContractFacts(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "disk.vhdx")
	manifest := filepath.Join(dir, "manifest.json")
	for _, mode := range []string{"matching", "missing", "old", "future", "malformed", "trailing", "oversize", "unprotected", "wrong image"} {
		t.Run(mode, func(t *testing.T) {
			_ = os.Remove(manifest)
			value := map[string]any{"windows_contract": guestagent.WindowsContract, "output": image, "agent_sha256": strings.Repeat("a", 64)}
			switch mode {
			case "old":
				delete(value, "windows_contract")
			case "future":
				value["windows_contract"] = guestagent.WindowsContract + 1
			case "wrong image":
				value["output"] = filepath.Join(dir, "other.vhdx")
			}
			b, _ := json.Marshal(value)
			switch mode {
			case "malformed":
				b = []byte("invalid")
			case "trailing":
				b = append(b, []byte("{}")...)
			case "oversize":
				b = []byte(strings.Repeat(" ", 65537))
			}
			if mode != "missing" {
				if err := os.WriteFile(manifest, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			checks := 0
			got := imageContract(image, func(string) error {
				checks++
				if mode == "unprotected" {
					return errors.New("unprotected")
				}
				return nil
			})
			want := 0
			if mode == "matching" {
				want = guestagent.WindowsContract
			}
			if mode == "future" {
				want = guestagent.WindowsContract + 1
			}
			if got != want || checks == 0 {
				t.Fatal("image contract did not fail closed", got)
			}
		})
	}
}

func TestInfoReportsEachConfiguredImageContract(t *testing.T) {
	server, _ := serverFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "disk.vhdx")
	data, _ := json.Marshal(map[string]any{"windows_contract": guestagent.WindowsContract, "output": path})
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	server.cfg.Images = map[string]string{"new": path, "old": filepath.Join(t.TempDir(), "old.vhdx")}
	info := server.info()
	if info.ImageContracts["new"] != guestagent.WindowsContract || info.ImageContracts["old"] != 0 || len(info.Images) != 2 {
		t.Fatal("missing image contract facts")
	}
}
