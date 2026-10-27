package wintools

import (
	"archive/zip"
	"errors"
	"io"
	"os"
	"path"
	"strings"
)

func safeEntry(name string) bool {
	if name == "" || len(name) > 220 || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") {
		return false
	}
	for _, component := range strings.Split(strings.TrimSuffix(name, "/"), "/") {
		if component == "" || component == "." || component == ".." || strings.TrimRight(component, ". ") != component {
			return false
		}
		base := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
			(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return false
		}
		for _, r := range component {
			if r < 32 || r > 126 || strings.ContainsRune(`<>"|?*`, r) {
				return false
			}
		}
	}
	return true
}

// Extract verifies the archive pin and every entry before writing into an
// existing empty owned directory. It never overwrites a file or follows a link
// outside that directory. Failed installations are discarded with the guest.
func Extract(archive, directory string, recipe Recipe) error {
	file, err := os.Open(archive)
	if err != nil {
		return errors.New("tool ZIP unavailable")
	}
	defer func() { _ = file.Close() }()
	if err := verify(file, recipe); err != nil {
		return err
	}
	reader, err := zip.NewReader(file, recipe.Bytes)
	if err != nil {
		return errors.New("tool ZIP invalid")
	}
	if len(reader.File) < 1 || len(reader.File) > 20000 {
		return errors.New("tool ZIP entry bound exceeded")
	}
	seen, total := map[string]bool{}, uint64(0)
	for _, entry := range reader.File {
		key := strings.ToLower(strings.TrimSuffix(entry.Name, "/"))
		kind := entry.Mode() & os.ModeType
		if !safeEntry(entry.Name) || seen[key] || (kind != 0 && kind != os.ModeDir) || entry.UncompressedSize64 > 128<<20 {
			return errors.New("tool ZIP entry refused")
		}
		seen[key] = true
		total += entry.UncompressedSize64
		if total > 512<<20 {
			return errors.New("tool ZIP expansion bound exceeded")
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return errors.New("tool extraction root unavailable")
	}
	defer func() { _ = root.Close() }()
	entries, err := root.Open(".")
	if err != nil {
		return errors.New("tool extraction root unreadable")
	}
	names, readErr := entries.Readdirnames(1)
	_ = entries.Close()
	if len(names) != 0 || readErr != io.EOF {
		return errors.New("empty tool extraction root required")
	}
	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() {
			if recipe.OmitPrefix != "" && strings.HasPrefix(entry.Name, recipe.OmitPrefix) {
				continue
			}
			if root.MkdirAll(strings.TrimSuffix(entry.Name, "/"), 0o700) != nil {
				return errors.New("tool directory creation failed")
			}
			continue
		}
		// CLI CMake retains modules, text help, ctest/cpack and licenses. Every
		// entry was checked above, including omitted HTML and the GUI binary.
		if (recipe.OmitPrefix != "" && strings.HasPrefix(entry.Name, recipe.OmitPrefix)) || (recipe.OmitFile != "" && entry.Name == recipe.OmitFile) {
			continue
		}
		if root.MkdirAll(path.Dir(entry.Name), 0o700) != nil {
			return errors.New("tool parent creation failed")
		}
		in, err := entry.Open()
		if err != nil {
			return errors.New("tool ZIP stream unavailable")
		}
		out, err := root.OpenFile(entry.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = in.Close()
			return errors.New("fresh tool file required")
		}
		n, copyErr := io.Copy(out, io.LimitReader(in, 128<<20+1))
		err = errors.Join(copyErr, out.Close(), in.Close())
		if err != nil || n < 0 || uint64(n) != entry.UncompressedSize64 {
			return errors.New("tool extraction incomplete")
		}
	}
	return nil
}
