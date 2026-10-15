package tart

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/redact"
)

// Diagnostics bounds, across both guest archives of one collection. The
// guest is untrusted by the time it is collected, so its archives are
// streamed: compressed and decompressed bytes, entries, and extracted bytes
// are all capped, and every file is redacted before it reaches disk.
const (
	maxDiagEntries = 1024
	maxDiagBytes   = 128 << 20 // extracted file contents
	maxDiagStream  = 192 << 20 // compressed, and decompressed tar, per archive
)

var (
	errDiagEntries = fmt.Errorf("guest diagnostics exceed %d entries", maxDiagEntries)
	errDiagBytes   = fmt.Errorf("guest diagnostics exceed %d bytes", maxDiagBytes)
	errDiagStream  = fmt.Errorf("guest diagnostic archive exceeds %d bytes", maxDiagStream)
	errDiagStopped = errors.New("diagnostic extraction stopped")
)

type diagBudget struct {
	entries int
	bytes   int64
	stream  int64 // per archive, compressed and decompressed
}

func newDiagBudget() *diagBudget {
	return &diagBudget{entries: maxDiagEntries, bytes: maxDiagBytes, stream: maxDiagStream}
}

// CollectDiagnostics implements provider.Provider: the runner's _diag
// directory, its stdout, and the launch command line as the host saw it.
func (p *Provider) CollectDiagnostics(ctx context.Context, name, dir string) error {
	if err := p.ownsGuest(name); err != nil {
		return err
	}
	budget := newDiagBudget()
	var errs []error
	for _, part := range []struct{ mode, sub string }{{"diag", "guest"}, {"diag-runner", "runner"}} {
		args := []string{"exec", name, guestPath, part.mode, p.cfg.RunnerDir}
		if err := p.collectArchive(ctx, args, filepath.Join(dir, part.sub), budget); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", part.mode, err))
		}
	}
	if pid := p.LaunchPID(name); pid > 0 {
		ps := CLI{Binary: "/bin/ps"}
		if out, err := output(ctx, ps, []string{"-o", "args=", "-p", strconv.Itoa(pid)}, nil, 4<<10); err == nil {
			_ = os.WriteFile(filepath.Join(dir, "launch-process.txt"), redact.Bytes(out), 0o600)
		}
	}
	return errors.Join(errs...)
}

// runFailure carries the guest command's own error through the pipe.
type runFailure struct{ err error }

func (r runFailure) Error() string { return r.err.Error() }
func (r runFailure) Unwrap() error { return r.err }

// collectArchive streams one gzip tar from the guest into dir.
func (p *Provider) collectArchive(ctx context.Context, args []string, dir string, budget *diagBudget) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pr, pw := io.Pipe()
	ran := make(chan error, 1)
	go func() {
		err := p.exec.Run(ctx, args, nil, &capWriter{w: pw, remaining: budget.stream})
		if err != nil {
			_ = pw.CloseWithError(runFailure{err})
		} else {
			_ = pw.Close()
		}
		ran <- err
	}()
	err := extractDiagnostics(pr, dir, budget)
	if err == nil {
		// Let the command finish normally; capWriter bounds any trailing bytes.
		_, err = io.Copy(io.Discard, pr)
	}
	if err != nil {
		cancel()
	}
	_ = pr.CloseWithError(errDiagStopped)
	runErr := <-ran
	var rf runFailure
	if err != nil && !errors.As(err, &rf) {
		return err
	}
	return runErr
}

// capWriter fails once more than remaining bytes are written.
type capWriter struct {
	w         io.Writer
	remaining int64
}

func (c *capWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.remaining {
		return 0, errDiagStream
	}
	c.remaining -= int64(len(p))
	return c.w.Write(p)
}

// capReader fails once more than remaining bytes are read.
type capReader struct {
	r         io.Reader
	remaining int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, errDiagStream
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	return n, err
}

// dropWriter forwards at most remaining bytes and silently discards the rest.
// It never fails, so a child writing through it is never cut off.
type dropWriter struct {
	w         io.Writer
	remaining int64
}

// launchLogLimit bounds launch output copied by this process.
const launchLogLimit = 1 << 20

func (d *dropWriter) Write(p []byte) (int, error) {
	n := min(int64(len(p)), d.remaining)
	if n > 0 {
		if _, err := d.w.Write(p[:n]); err != nil {
			d.remaining = 0
		} else {
			d.remaining -= n
		}
	}
	return len(p), nil
}

// extractDiagnostics extracts a gzip tar stream into dir. Only directories
// and regular files are created, under an os.Root, each file through the
// redactor; the optional performance report is validated and re-encoded.
// An empty stream (nothing to collect) succeeds.
func extractDiagnostics(r io.Reader, dir string, budget *diagBudget) error {
	gz, err := gzip.NewReader(&capReader{r: r, remaining: budget.stream})
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("invalid guest diagnostic archive: %w", err)
	}
	defer func() { _ = gz.Close() }()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	tr := tar.NewReader(&capReader{r: gz, remaining: budget.stream})
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read guest diagnostic archive: %w", err)
		}
		budget.entries--
		if budget.entries < 0 {
			return errDiagEntries
		}
		name := path.Clean(h.Name)
		if name == "." {
			continue
		}
		local := filepath.FromSlash(name)
		if !filepath.IsLocal(local) || strings.ContainsAny(name, "\\\x00") {
			return errors.New("unsafe guest diagnostic path")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(local, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if h.Size > budget.bytes {
				return errDiagBytes
			}
			budget.bytes -= h.Size
			if parent := filepath.Dir(local); parent != "." {
				if err := root.MkdirAll(parent, 0o700); err != nil {
					return err
				}
			}
			if err := extractFile(root, local, tr); err != nil {
				return err
			}
		}
		// Links, devices and other types are skipped, never created.
	}
}

func extractFile(root *os.Root, local string, r io.Reader) error {
	if local == perf.FileName {
		report, decodeErr := perf.DecodeReport(r)
		if decodeErr != nil {
			return nil //nolint:nilerr // Optional telemetry must not prevent collecting official logs.
		}
		data, err := json.Marshal(report)
		if err != nil {
			return err
		}
		f, err := root.OpenFile(local, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, err = f.Write(redact.Bytes(data))
		return errors.Join(err, f.Close())
	}
	f, err := root.OpenFile(local, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	sink := redact.NewWriter(f)
	_, err = io.Copy(sink, r)
	return errors.Join(err, sink.Close(), f.Close())
}
