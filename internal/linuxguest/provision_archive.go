package linuxguest

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"path"
	"strings"
)

const provisionArchiveLimit = 1 << 30
const provisionExtractLimit = 8 << 30
const provisionEntryLimit = 100000

type provisionEntry struct {
	name, link string
	kind       byte
	size       int64
	mode       fs.FileMode
}

func provisionArchiveName(name string) (string, error) {
	if name == "" || len(name) > 4096 || strings.ContainsAny(name, "\\:\x00\r\n") || path.IsAbs(name) {
		return "", errors.New("unsafe runner archive path")
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", errors.New("runner archive traversal")
		}
	}
	name = path.Clean(name)
	if name == "." {
		return name, nil
	}
	if name == "" || strings.HasPrefix(name, "../") {
		return "", errors.New("unsafe runner archive path")
	}
	return name, nil
}

func provisionArchiveEntry(h *tar.Header) (provisionEntry, error) {
	name, err := provisionArchiveName(h.Name)
	if err != nil {
		return provisionEntry{}, err
	}
	e := provisionEntry{name: name, kind: h.Typeflag, size: h.Size, mode: fs.FileMode(h.Mode & 0777)}
	if name == "." && h.Typeflag != tar.TypeDir || h.Size < 0 || h.Size > provisionExtractLimit {
		return e, errors.New("invalid runner archive entry")
	}
	switch h.Typeflag {
	case tar.TypeDir, tar.TypeReg:
	case tar.TypeSymlink, tar.TypeLink:
		target := h.Linkname
		if h.Typeflag == tar.TypeSymlink {
			// #nosec G305 -- Lexical link planning only; the full plan rejects escapes/link parents, and extraction uses os.Root.
			target = path.Join(path.Dir(name), target)
		}
		// Validate the literal target first: path.Join would hide an absolute path.
		if h.Linkname == "" || path.IsAbs(h.Linkname) || strings.ContainsAny(h.Linkname, "\\:\x00\r\n") {
			return e, errors.New("unsafe runner archive link")
		}
		e.link, err = provisionArchiveName(target)
		if err != nil || e.link == "." {
			return e, errors.New("escaping runner archive link")
		}
	default:
		return e, errors.New("unsupported runner archive entry")
	}
	for _, reserved := range []string{".runner", ".credentials", ".credentials_rsaparams", "_work", "_diag"} {
		if name == reserved || strings.HasPrefix(name, reserved+"/") {
			return e, errors.New("runner archive contains enrollment or job state")
		}
	}
	return e, nil
}

// Pin the exact opened archive before returning a bounded, fully validated plan.
// Link parents and hard links to non-regular entries are refused independent of
// archive ordering; extraction never follows an archive-created link.
func planProvisionArchive(source io.ReadSeeker, expected string) ([]provisionEntry, error) {
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(source, provisionArchiveLimit+1))
	if err != nil || n > provisionArchiveLimit || hex.EncodeToString(hash.Sum(nil)) != expected {
		return nil, errors.New("runner archive SHA-256 or size differs")
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	compressed, err := gzip.NewReader(source)
	if err != nil {
		return nil, errors.New("runner archive must be gzip")
	}
	defer func() { _ = compressed.Close() }()
	reader := tar.NewReader(compressed)
	entries := []provisionEntry{}
	names := map[string]byte{}
	var size int64
	for {
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("invalid runner archive")
		}
		e, err := provisionArchiveEntry(h)
		if err != nil {
			return nil, err
		}
		size += e.size
		if len(entries) >= provisionEntryLimit || size > provisionExtractLimit {
			return nil, errors.New("runner archive exceeds recipe bounds")
		}
		if _, duplicate := names[e.name]; duplicate {
			return nil, errors.New("duplicate runner archive path")
		}
		names[e.name] = e.kind
		entries = append(entries, e)
	}
	for _, e := range entries {
		for parent := path.Dir(e.name); parent != "."; parent = path.Dir(parent) {
			if kind, found := names[parent]; found && kind != tar.TypeDir {
				return nil, errors.New("runner archive parent is not a directory")
			}
		}
		if e.kind == tar.TypeLink && names[e.link] != tar.TypeReg {
			return nil, errors.New("runner archive hard link is not a regular file")
		}
	}
	for _, name := range []string{"bin/Runner.Listener", "bin/installdependencies.sh", "run.sh", "config.sh"} {
		if names[name] != tar.TypeReg {
			return nil, errors.New("runner archive lacks required official runner files")
		}
	}
	if n, err := io.Copy(io.Discard, io.LimitReader(compressed, 1<<20+1)); err != nil || n > 1<<20 {
		return nil, errors.New("runner archive checksum failed")
	}
	return entries, nil
}
