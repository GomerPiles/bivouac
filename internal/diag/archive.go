package diag

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/redact"
)

// ExtractGuestArchive is the bounded, path-checked, redacted host sink shared
// by the Windows and Linux guest transports. The archive is always untrusted:
// only runner.log, the performance report and _diag/ entries are accepted.
func ExtractGuestArchive(path, destination string) error {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return errors.New("invalid guest diagnostic archive")
	}
	defer func() { _ = reader.Close() }()
	if len(reader.File) > 1024 {
		return errors.New("too many guest diagnostic files")
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	var total uint64
	for _, file := range reader.File {
		name := file.Name
		if file.Mode().IsDir() {
			continue
		}
		if !file.Mode().IsRegular() || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") || strings.Contains(name, "..") || (name != "runner.log" && name != perf.FileName && !strings.HasPrefix(name, "_diag/")) {
			return errors.New("unsafe guest diagnostic path")
		}
		total += file.UncompressedSize64
		if file.UncompressedSize64 > 16<<20 || total > 128<<20 {
			return errors.New("guest diagnostics exceed bound")
		}
		if err := root.MkdirAll(filepath.Dir(filepath.FromSlash(name)), 0o700); err != nil {
			return err
		}
		input, err := file.Open()
		if err != nil {
			return err
		}
		if name == perf.FileName {
			report, readErr := perf.DecodeReport(input)
			_ = input.Close()
			if readErr != nil {
				// Optional telemetry must not prevent collecting official logs.
				continue
			}
			output, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			sink := redact.NewWriter(output)
			err = errors.Join(json.NewEncoder(sink).Encode(report), sink.Close(), output.Close())
			if err != nil {
				return err
			}
			continue
		}
		output, err := root.OpenFile(filepath.FromSlash(name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = input.Close()
			return err
		}
		sink := redact.NewWriter(output)
		_, copyErr := io.Copy(sink, io.LimitReader(input, 16<<20+1))
		err = errors.Join(copyErr, sink.Close(), output.Close(), input.Close())
		if err != nil {
			return err
		}
	}
	return nil
}
