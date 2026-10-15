// Package diag preserves a guest's runner logs and launch record on the host
// before the guest is deleted, with every text file redacted.
package diag

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/redact"
	"github.com/GomerPiles/bivouac/internal/state"
)

// Collect writes the provider's diagnostics for name into dir, plus a
// summary of the instance record, then redacts every file in dir. Providers
// redact while extracting; this pass is a second, independent sink check.
func Collect(ctx context.Context, p provider.Provider, name, dir string, inst *state.Instance, reason string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	summary := map[string]any{"instance": inst, "reason": reason, "provider": p.Name()}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err == nil {
		_ = os.WriteFile(filepath.Join(dir, "instance.json"), redact.Bytes(data), 0o600)
	}
	collectErr := p.CollectDiagnostics(ctx, name, dir)
	if err := RedactDir(dir); err != nil {
		return fmt.Errorf("redact %s: %w", dir, err)
	}
	return collectErr
}

// RedactDir rewrites every regular file under dir through a streaming
// redactor, so memory stays bounded by [redact.MaxLine] whatever the file
// sizes. A file that cannot be redacted is removed rather than left behind,
// and the walk continues; all failures are returned together. Other entry
// types (symbolic links, devices) are removed without being followed.
func RedactDir(dir string) error {
	var errs []error
	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, err)
			if d != nil && d.IsDir() && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case d.IsDir():
			return nil
		case d.Type().IsRegular():
			if err := redactFile(path); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(path), err))
				if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
					errs = append(errs, rmErr)
				}
			}
		default:
			if err := os.Remove(path); err != nil {
				errs = append(errs, err)
			}
		}
		return nil
	})
	return errors.Join(append(errs, walkErr)...)
}

func redactFile(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".redact-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	w := redact.NewWriter(tmp)
	_, copyErr := io.Copy(w, in)
	if err := errors.Join(copyErr, w.Close(), tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
