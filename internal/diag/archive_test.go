package diag

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/perf"
)

func diagnosticFixture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	file, err := w.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestGuestDiagnosticsRejectUnsafePathsAndRedactAtSink(t *testing.T) {
	for _, name := range []string{"../escape.log", "/absolute.log", "_diag/../../escape.log", `_diag\escape.log`, "jit", "config.json", "_diag/C:drive.log"} {
		if err := ExtractGuestArchive(diagnosticFixture(t, name, "fixture"), t.TempDir()); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	destination := t.TempDir()
	if err := ExtractGuestArchive(diagnosticFixture(t, "_diag/Runner.log", "Authorization: Bearer synthetic-secret\n"), destination); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(destination, "_diag", "Runner.log"))
	if err != nil || strings.Contains(string(data), "synthetic-secret") || !strings.Contains(string(data), "<redacted>") {
		t.Fatal("diagnostic sink did not redact")
	}
}
func TestGuestDiagnosticsRejectExpansionBomb(t *testing.T) {
	path := diagnosticFixture(t, "runner.log", strings.Repeat("x", 16<<20+1))
	if err := ExtractGuestArchive(path, t.TempDir()); err == nil {
		t.Fatal("expansion bound ignored")
	}
}

func TestGuestDiagnosticsValidateOptionalPerformanceAndKeepOfficialLogs(t *testing.T) {
	now := time.Now().UTC()
	report := perf.Report{StartedAt: now, Latest: perf.Sample{At: now, TotalBytes: 100, AvailableBytes: 80, LogicalCPUs: 2}, Samples: 1, PeakUsedBytes: 20, MinimumAvailableBytes: 80, Disk: &perf.DiskReport{Latest: perf.DiskSpace{TotalBytes: 100, AvailableBytes: 30}, Samples: 1, MinimumAvailableBytes: 30}}
	valid, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	valid = append(valid[:len(valid)-1], []byte(`,"unknown":"synthetic-private-value"}`)...)
	for _, content := range []string{string(valid), "invalid", strings.Repeat("x", 64<<10+1), `{"latest":{"cpu_percent":101}}`} {
		t.Run(fmt.Sprintf("bytes-%d", len(content)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture.zip")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			archive := zip.NewWriter(f)
			for _, entry := range []struct{ name, data string }{{"runner.log", "listener log"}, {perf.FileName, content}, {"_diag/Worker.log", "official log"}} {
				writer, err := archive.Create(entry.name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(writer, entry.data); err != nil {
					t.Fatal(err)
				}
			}
			if err := errors.Join(archive.Close(), f.Close()); err != nil {
				t.Fatal(err)
			}
			destination := t.TempDir()
			if err := ExtractGuestArchive(path, destination); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(filepath.Join(destination, "_diag", "Worker.log")); err != nil || string(data) != "official log" {
				t.Fatal("optional report prevented official diagnostics", err)
			}
			data, err := os.ReadFile(filepath.Join(destination, perf.FileName))
			if content == string(valid) {
				if err != nil || strings.Contains(string(data), "synthetic-private-value") {
					t.Fatal("untrusted report fields persisted", err)
				}
				if decoded, err := perf.ReadReport(destination); err != nil || decoded.PeakUsedBytes != 20 || decoded.Disk == nil || decoded.Disk.MinimumAvailableBytes != 30 {
					t.Fatal("numeric report was not preserved", err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("invalid optional report persisted", err)
			}
		})
	}
}
