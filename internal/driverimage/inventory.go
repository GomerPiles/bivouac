// Package driverimage prepares immutable Windows GPU images from a prepared
// base and the active host driver packages. Runtime guests receive no shares.
package driverimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxFiles = 8192
const maxBytes int64 = 2 << 30

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Package struct {
	Name  string `json:"name"`
	Files []File `json:"files"`
}

// PayloadFile excludes host runtime diagnostics that AMD writes inside its
// installed package. They may grow while being read and are never image input.
func PayloadFile(name string) bool { return !strings.EqualFold(filepath.Ext(name), ".log") }

func inventory(ctx context.Context, paths []string, check func(string) error) ([]Package, error) {
	paths = append([]string(nil), paths...)
	sort.Strings(paths)
	var packages []Package
	var total int64
	count := 0
	seen := map[string]bool{}
	for _, path := range paths {
		if err := check(path); err != nil {
			return nil, errors.New("GPU package is not protected")
		}
		name := filepath.Base(path)
		if seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true
		root, err := os.OpenRoot(path)
		if err != nil {
			return nil, errors.New("GPU package unavailable")
		}
		p := Package{Name: name}
		err = fs.WalkDir(root.FS(), ".", func(relative string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return errors.New("GPU package cannot be read")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("GPU package contains a link")
			}
			if entry.IsDir() {
				return nil
			}
			if !PayloadFile(relative) {
				return nil
			}
			if len(relative) > 240 {
				return errors.New("GPU package path exceeds bound")
			}
			if err := check(filepath.Join(path, filepath.FromSlash(relative))); err != nil {
				return errors.New("GPU payload is not protected")
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() < 0 {
				return errors.New("GPU payload is not a regular file")
			}
			if count >= maxFiles || info.Size() > maxBytes-total {
				return errors.New("GPU payload exceeds 8192 files or 2 GiB")
			}
			count++
			total += info.Size()
			f, err := root.Open(relative)
			if err != nil {
				return errors.New("GPU payload unavailable")
			}
			h := sha256.New()
			n, e := copyBounded(ctx, h, f, info.Size())
			err = errors.Join(e, f.Close())
			if err != nil || n != info.Size() {
				return errors.New("GPU payload changed during inventory")
			}
			p.Files = append(p.Files, File{Path: relative, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
			return nil
		})
		err = errors.Join(err, root.Close())
		if err != nil {
			return nil, err
		}
		if len(p.Files) == 0 {
			return nil, errors.New("GPU package has no payload")
		}
		packages = append(packages, p)
	}
	if len(packages) == 0 || len(packages) > 8 {
		return nil, errors.New("GPU inventory requires 1-8 packages")
	}
	return packages, nil
}

func imageKey(baseHash string, packages []Package) string {
	scriptHash := sha256.Sum256([]byte(prepareScript))
	b, _ := json.Marshal(struct {
		Script   [32]byte
		Base     string
		Packages []Package
	}{scriptHash, baseHash, packages})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func copyBounded(ctx context.Context, w io.Writer, r io.Reader, limit int64) (int64, error) {
	buffer := make([]byte, 1<<20)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := r.Read(buffer)
		if int64(n) > limit-total {
			return total, errors.New("GPU input exceeds byte bound")
		}
		if n > 0 {
			m, e := w.Write(buffer[:n])
			total += int64(m)
			if e != nil {
				return total, e
			}
			if m != n {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return total, errors.New("GPU input read failed")
		}
	}
}
