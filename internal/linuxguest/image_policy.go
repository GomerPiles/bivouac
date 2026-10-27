package linuxguest

import (
	"errors"
	"io"
	"os"
	"strings"
)

// Factory-only sanitation permits empty work directories and bounded Runner
// startup logs. Worker logs, job files, credentials, links and unknown entries
// refuse capture. The raw source and any live runner remain untouched.
func sanitizeRunnerFactory(root string) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("image factory runner root is not an ordinary directory")
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	for _, name := range []string{".runner", ".credentials", ".credentials_rsaparams"} {
		if _, e := r.Lstat(name); !errors.Is(e, os.ErrNotExist) {
			return errors.New("image factory refuses runner enrollment")
		}
	}
	for _, name := range []string{"_work", "_diag"} {
		info, e := r.Lstat(name)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("image factory runner state is not an ordinary directory")
		}
		directory, e := r.Open(name)
		if e != nil {
			return e
		}
		entries, readErr := directory.ReadDir(1025)
		closeErr := directory.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if name == "_work" && len(entries) != 0 || len(entries) > 1024 {
			return errors.New("image factory refuses job state or excess diagnostics")
		}
		var total int64
		for _, entry := range entries {
			info, e := entry.Info()
			if e != nil || !info.Mode().IsRegular() || !strings.HasPrefix(entry.Name(), "Runner_") || !strings.HasSuffix(entry.Name(), ".log") || info.Size() > 16<<20 {
				return errors.New("image factory refuses unknown runner diagnostics")
			}
			total += info.Size()
			if total > 128<<20 {
				return errors.New("image factory diagnostics exceed bound")
			}
		}
		for _, entry := range entries {
			if e = r.Remove(name + "/" + entry.Name()); e != nil {
				return e
			}
		}
		if e = r.Remove(name); e != nil {
			return e
		}
	}
	return nil
}
