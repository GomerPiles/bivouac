package tart

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/perf"
)

func TestTartDiagnosticsValidateOptionalPerformanceAndKeepLogs(t *testing.T) {
	now := time.Now().UTC()
	report := perf.Report{StartedAt: now, Latest: perf.Sample{At: now, TotalBytes: 1000, AvailableBytes: 500, LogicalCPUs: 1}, Samples: 1}
	valid, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	valid = append(valid[:len(valid)-1], []byte(`,"unknown":"synthetic-private-field"}`)...)
	for _, data := range [][]byte{valid, []byte("malformed"), bytes.Repeat([]byte("x"), 64<<10+1)} {
		var archive bytes.Buffer
		gz := gzip.NewWriter(&archive)
		tw := tar.NewWriter(gz)
		for _, entry := range []struct {
			name string
			data []byte
		}{{"./performance.json", data}, {"runner.log", []byte("official runner log")}} {
			if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o600, Size: int64(len(entry.data))}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		directory := t.TempDir()
		if err := extractDiagnostics(bytes.NewReader(archive.Bytes()), directory, newDiagBudget()); err != nil {
			t.Fatal(err)
		}
		log, err := os.ReadFile(filepath.Join(directory, "runner.log"))
		if err != nil || string(log) != "official runner log" {
			t.Fatal("optional report lost logs", err)
		}
		retained, err := os.ReadFile(filepath.Join(directory, perf.FileName))
		if bytes.Equal(data, valid) {
			if err != nil || strings.Contains(string(retained), "synthetic-private") {
				t.Fatal("report was not sanitized", err)
			}
		} else if !os.IsNotExist(err) {
			t.Fatal("malformed optional report persisted", err)
		}
	}
}
