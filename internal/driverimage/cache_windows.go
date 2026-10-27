//go:build windows

package driverimage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/GomerPiles/bivouac/internal/command"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/winhost"
	"github.com/Microsoft/go-winio/vhd"
	"golang.org/x/sys/windows"
)

type base struct {
	file *os.File
	hash string
}

// Cache owns pinned immutable base files for its lifetime. Its process lock and
// protected root prevent another publisher from modifying a selected parent.
// Older generations remain available to already-running guests; no eviction
// or mutation of a published image is performed.
type Cache struct {
	mu         sync.Mutex
	root       string
	lock       *control.Lock
	bases      map[string]base
	discover   func() ([]string, error)
	check      func(string) error
	prepare    func(context.Context, string, string, []string, []Package) error
	createDisk func(string, string) error
	grant      func(string) error
	space      func(string, int64) error
	closed     bool
}

type receipt struct {
	Key        string    `json:"key"`
	Base       string    `json:"base"`
	BaseSHA256 string    `json:"base_sha256"`
	Packages   []Package `json:"packages"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
}

func Open(root string) (*Cache, error) {
	if !filepath.IsAbs(root) || strings.HasPrefix(root, `\\`) {
		return nil, errors.New("GPU cache requires a local absolute root")
	}
	if err := winhost.CheckProtectedParents(root); err != nil {
		return nil, errors.New("GPU cache parent is not protected")
	}
	if err := os.Mkdir(root, 0700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	} else if err := grantRead(root); err != nil {
		return nil, err
	}
	if err := winhost.CheckProtected(root); err != nil {
		return nil, errors.New("GPU cache is not protected")
	}
	lock, err := (control.Files{Dir: root}).Acquire()
	if err != nil {
		return nil, errors.New("GPU cache is already in use")
	}
	return &Cache{root: root, lock: lock, bases: map[string]base{}, discover: Discover, check: winhost.CheckProtected, prepare: prepare, createDisk: func(child, parent string) error { return vhd.CreateDiffVhd(child, parent, 0) }, grant: grantRead, space: requireSpace}, nil
}

func (c *Cache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	var errs []error
	for name, b := range c.bases {
		errs = append(errs, b.file.Close())
		delete(c.bases, name)
	}
	if c.lock != nil {
		errs = append(errs, c.lock.Release())
		c.lock = nil
	}
	return errors.Join(errs...)
}

// Ensure discovers and fingerprints the active packages on every launch.
// A cache hit avoids copying, mounting, booting or changing the base image.
// Its return value is an immutable parent for a per-job differencing disk.
func (c *Cache) Ensure(ctx context.Context, source string) (string, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return "", false, errors.New("GPU cache is closed")
	}
	b, err := c.pinBase(ctx, source)
	if err != nil {
		return "", false, err
	}
	paths, err := c.discover()
	if err != nil {
		return "", false, err
	}
	packages, err := inventory(ctx, paths, c.check)
	if err != nil {
		return "", false, err
	}
	key := imageKey(b.hash+"|"+strings.ToLower(source), packages)
	destination := filepath.Join(c.root, key)
	if _, err = os.Lstat(destination); err == nil {
		path, err := c.readPublished(ctx, destination, source, b.hash, key)
		return path, true, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, errors.New("GPU cache cannot be inspected")
	}
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return "", false, err
	}
	if len(entries) > 64 {
		return "", false, errors.New("GPU image cache is full; retain active parents and remove unused generations explicitly")
	}
	var payloadBytes int64
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			payloadBytes += file.Size
		}
	}
	if c.space != nil {
		if err := c.space(c.root, 2*payloadBytes+(5<<30)); err != nil {
			return "", false, err
		}
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return "", false, err
	}
	workspace := filepath.Join(c.root, "bivouac-gpu-"+hex.EncodeToString(random[:]))
	if err = os.Mkdir(workspace, 0700); err != nil {
		return "", false, err
	}
	if err = c.check(workspace); err != nil {
		return "", false, errors.New("GPU workspace is not protected")
	}
	// Failure deliberately retains this exact private workspace. An interrupted
	// mount is never recursively deleted or treated as a reusable cache hit.
	marker := struct {
		Workspace string `json:"workspace"`
		Key       string `json:"key"`
	}{workspace, key}
	if err = writeJSON(filepath.Join(workspace, "owner.json"), marker); err != nil {
		return "", false, err
	}
	disk := filepath.Join(workspace, "disk.vhdx")
	if err = c.createDisk(disk, source); err != nil {
		return "", false, errors.New("GPU differencing image creation failed")
	}
	if err = c.prepare(ctx, workspace, disk, paths, packages); err != nil {
		return "", false, err
	}
	// Recheck after preparation: a driver installation during capture cannot
	// publish a mixed generation. Existing jobs are never touched.
	currentPaths, err := c.discover()
	if err != nil {
		return "", false, err
	}
	current, err := inventory(ctx, currentPaths, c.check)
	if err != nil {
		return "", false, err
	}
	if imageKey(b.hash+"|"+strings.ToLower(source), current) != key {
		return "", false, errors.New("host GPU driver changed during image preparation; retry after installation completes")
	}
	file, err := openPinned(disk)
	if err != nil {
		return "", false, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return "", false, err
	}
	hash, err := hashReader(ctx, file, info.Size())
	err = errors.Join(err, file.Close())
	if err != nil {
		return "", false, err
	}
	if err = c.grant(disk); err != nil {
		return "", false, err
	}
	if err = c.grant(workspace); err != nil {
		return "", false, err
	}
	r := receipt{Key: key, Base: source, BaseSHA256: b.hash, Packages: packages, Size: info.Size(), SHA256: hash}
	if err = writeJSON(filepath.Join(workspace, "receipt.json"), r); err != nil {
		return "", false, err
	}
	// The directory name is the publication marker. Never overwrite one, even
	// after failed validation; the service lock serializes all publishers.
	if err = os.Rename(workspace, destination); err != nil {
		return "", false, errors.New("GPU image publication failed; workspace retained")
	}
	return filepath.Join(destination, "disk.vhdx"), false, nil
}

func (c *Cache) pinBase(ctx context.Context, path string) (base, error) {
	if b, ok := c.bases[path]; ok {
		return b, nil
	}
	if err := c.check(path); err != nil {
		return base{}, errors.New("GPU base image is not protected")
	}
	f, err := openPinned(path)
	if err != nil {
		return base{}, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 256<<30 {
		return base{}, errors.New("GPU base image exceeds bound")
	}
	metadata := filepath.Join(filepath.Dir(path), "manifest.json")
	if c.check(metadata) != nil {
		return base{}, errors.New("GPU base manifest is not protected")
	}
	data, err := readBounded(metadata, 65536)
	if err != nil {
		return base{}, err
	}
	var manifest struct {
		Output string `json:"output"`
		SHA256 string `json:"sha256"`
	}
	if json.Unmarshal(data, &manifest) != nil || !strings.EqualFold(manifest.Output, path) || len(manifest.SHA256) != 64 {
		return base{}, errors.New("GPU base manifest identity differs")
	}
	hash, err := hashReader(ctx, f, info.Size())
	if err != nil || !strings.EqualFold(hash, manifest.SHA256) {
		return base{}, errors.New("GPU base image checksum differs")
	}
	b := base{file: f, hash: hash}
	c.bases[path] = b
	keep = true
	return b, nil
}

func (c *Cache) readPublished(ctx context.Context, dir, source, baseHash, key string) (string, error) {
	if c.check(dir) != nil {
		return "", errors.New("GPU cache generation is not protected")
	}
	raw, err := readBounded(filepath.Join(dir, "receipt.json"), 4<<20)
	if err != nil {
		return "", err
	}
	var r receipt
	if json.Unmarshal(raw, &r) != nil || r.Key != key || r.Base != source || r.BaseSHA256 != baseHash || imageKey(baseHash+"|"+strings.ToLower(source), r.Packages) != key {
		return "", errors.New("GPU cache receipt differs")
	}
	path := filepath.Join(dir, "disk.vhdx")
	if c.check(path) != nil {
		return "", errors.New("GPU cached image is not protected")
	}
	f, err := openPinned(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || info.Size() != r.Size {
		return "", errors.New("GPU cached image size differs")
	}
	hash, err := hashReader(ctx, f, r.Size)
	if err != nil || hash != r.SHA256 {
		return "", errors.New("GPU cached image checksum differs")
	}
	return path, nil
}

func openPinned(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("invalid GPU image path")
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New("GPU input could not be pinned read-only")
	}
	return os.NewFile(uintptr(h), path), nil
}
func hashReader(ctx context.Context, r io.Reader, size int64) (string, error) {
	h := sha256.New()
	n, err := copyBounded(ctx, h, r, size)
	if err != nil || n != size {
		return "", errors.New("GPU input size changed")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("GPU metadata unavailable")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("GPU metadata exceeds bound")
	}
	return b, nil
}
func writeJSON(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("GPU metadata cannot be created")
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}
func grantRead(path string) error {
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;S-1-5-83-0)")
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil)
}

func requireSpace(root string, required int64) error {
	path, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	var available, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(path, &available, &total, &free); err != nil {
		return errors.New("GPU cache free-space query failed")
	}
	if required < 0 || available < uint64(required) {
		return errors.New("GPU cache needs two payload copies plus 5 GiB free")
	}
	return nil
}

func prepare(ctx context.Context, workspace, disk string, paths []string, packages []Package) error {
	for _, p := range packages {
		var source string
		for _, path := range paths {
			if filepath.Base(path) == p.Name {
				source = path
				break
			}
		}
		if source == "" {
			return errors.New("GPU package disappeared")
		}
		dest := filepath.Join(workspace, "payload", p.Name)
		for _, file := range p.Files {
			if err := ctx.Err(); err != nil {
				return err
			}
			in, err := openPinned(filepath.Join(source, filepath.FromSlash(file.Path)))
			if err != nil {
				return err
			}
			target := filepath.Join(dest, filepath.FromSlash(file.Path))
			err = os.MkdirAll(filepath.Dir(target), 0700)
			if err != nil {
				_ = in.Close()
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				_ = in.Close()
				return err
			}
			h := sha256.New()
			n, e := copyBounded(ctx, io.MultiWriter(out, h), in, file.Size)
			err = errors.Join(e, in.Close(), out.Close())
			if err != nil || n != file.Size || hex.EncodeToString(h.Sum(nil)) != file.SHA256 {
				return errors.New("GPU payload changed during capture")
			}
		}
	}
	data, err := json.Marshal(struct {
		Workspace, Disk string
		Packages        []Package
	}{workspace, disk, packages})
	if err != nil {
		return err
	}
	path := filepath.Join(workspace, "prepare.ps1")
	if err = os.WriteFile(path, []byte(prepareScript), 0600); err != nil {
		return err
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	_, err = (command.Native{}).Input(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path}, data)
	if err != nil {
		return fmt.Errorf("GPU offline preparation failed; private workspace retained: %w", err)
	}
	// Staged source files and the fixed script are retained with the receipt:
	// no recursive cleanup can cross a potentially still-attached volume.
	return nil
}
