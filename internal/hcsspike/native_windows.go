//go:build windows

package hcsspike

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/provider/appsandbox"
	"github.com/Microsoft/go-winio/vhd"
	"golang.org/x/sys/windows"
)

type native struct {
	dll           *windows.LazyDLL
	preparedOwner string
	payloads      []payloadProof
}

// HcsGrantVmAccess deliberately adds the owned VM account to payload ACLs.
// Preserve the exact post-grant descriptor and file identity instead of
// incorrectly applying the administrator-only journal policy to those files.
type payloadProof struct {
	path     string
	identity os.FileInfo
	security string
}

func payloadSecurity(path string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", errors.New("cannot inspect spike payload permissions")
	}
	text := sd.String()
	if text == "" {
		return "", errors.New("cannot encode spike payload permissions")
	}
	return text, nil
}

func capturePayload(path string) (payloadProof, error) {
	info, err := os.Stat(path)
	if err != nil {
		return payloadProof{}, errors.New("cannot bind spike payload identity")
	}
	security, err := payloadSecurity(path)
	if err != nil {
		return payloadProof{}, err
	}
	return payloadProof{path: path, identity: info, security: security}, nil
}

func (p payloadProof) verify() error {
	current, err := os.Stat(p.path)
	if err != nil || !os.SameFile(p.identity, current) {
		return errors.New("spike payload file identity changed")
	}
	security, err := payloadSecurity(p.path)
	if err != nil {
		return err
	}
	if security != p.security {
		return errors.New("spike payload permissions changed after the owned VM grant")
	}
	return nil
}

type nativeSystem struct {
	api    *native
	handle uintptr
}

type nativeError struct {
	operation string
	code      uint32
}

func (e *nativeError) Error() string { return fmt.Sprintf("%s HRESULT 0x%08x", e.operation, e.code) }
func hresult(name string, result uintptr) error {
	code := uint32(result & 0xffffffff)
	if code&0x80000000 != 0 {
		return &nativeError{operation: name, code: code}
	}
	return nil
}

// Check resolves exports only, without calling HCS, opening any VM or reading
// production configuration, credentials, discovery files or ownership journals.
func Check() (map[string]any, error) {
	api := &native{dll: windows.NewLazySystemDLL("computecore.dll")}
	if err := api.check(); err != nil {
		return nil, err
	}
	disk := windows.NewLazySystemDLL("virtdisk.dll")
	if err := disk.NewProc("CreateVirtualDisk").Find(); err != nil {
		return nil, errors.New("CreateVirtualDisk unavailable")
	}
	return map[string]any{"architecture": runtime.GOARCH, "administrator": windows.GetCurrentProcessToken().IsElevated(), "hcs_exports": true, "virtual_disk_export": true, "live_vm_tested": false}, nil
}

func (a *native) check() error {
	if runtime.GOARCH != "amd64" {
		return errors.New("HCS spike supports Windows amd64 only")
	}
	for _, name := range []string{"HcsCreateOperation", "HcsCloseOperation", "HcsWaitForOperationResult", "HcsCreateComputeSystem", "HcsOpenComputeSystem", "HcsCloseComputeSystem", "HcsGetComputeSystemProperties", "HcsStartComputeSystem", "HcsModifyComputeSystem", "HcsTerminateComputeSystem", "HcsGrantVmAccess", "HcsCreateEmptyGuestStateFile", "HcsCreateEmptyRuntimeStateFile"} {
		if err := a.dll.NewProc(name).Find(); err != nil {
			return fmt.Errorf("required HCS export unavailable: %s", name)
		}
	}
	return nil
}

func (a *native) proc(name string) *windows.LazyProc { return a.dll.NewProc(name) }

func operationTimeout(ctx context.Context) (uintptr, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	bound := 30 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		bound = min(bound, time.Until(deadline))
	}
	if bound <= 0 {
		return 0, context.DeadlineExceeded
	}
	return uintptr(max(1, bound.Milliseconds())), nil
}

func boundedResult(p *uint16) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	words := make([]uint16, 0, 1024)
	for i := 0; i < 32768; i++ {
		word := *(*uint16)(unsafe.Add(unsafe.Pointer(p), i*2)) // #nosec G103 -- HCS returns a NUL-terminated UTF-16 allocation; inspect at most 64 KiB and stop at its terminator.
		if word == 0 {
			return []byte(windows.UTF16ToString(words)), nil
		}
		words = append(words, word)
	}
	return nil, errors.New("HCS result exceeds 64 KiB")
}

func (a *native) wait(ctx context.Context, op uintptr, wantResult bool) ([]byte, error) {
	bound, err := operationTimeout(ctx)
	if err != nil {
		return nil, err
	}
	var result *uint16
	r, _, _ := a.proc("HcsWaitForOperationResult").Call(op, bound, uintptr(unsafe.Pointer(&result))) // #nosec G103 -- Documented HCS ABI; results use LocalFree, including failure documents.
	if result != nil {
		defer func() { _, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(result)))) }()
	} // #nosec G103 -- Paired HCS allocation release.
	if err = hresult("HcsWaitForOperationResult", r); err != nil {
		return nil, err
	}
	if !wantResult {
		return nil, nil
	}
	return boundedResult(result)
}

func (a *native) operation(ctx context.Context, method string, handle uintptr, document string, wantResult bool) ([]byte, error) {
	if _, err := operationTimeout(ctx); err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(document)
	if err != nil {
		return nil, errors.New("invalid HCS document")
	}
	op, _, _ := a.proc("HcsCreateOperation").Call(0, 0)
	if op == 0 {
		return nil, errors.New("cannot allocate HCS operation")
	}
	defer func() { _, _, _ = a.proc("HcsCloseOperation").Call(op) }()
	r, _, _ := a.proc(method).Call(handle, op, uintptr(unsafe.Pointer(p)), 0) // #nosec G103 -- HCS Start/Terminate/GetProperties/Modify share these first three ABI arguments; unused fourth register is ignored.
	if err = hresult(method, r); err != nil {
		return nil, err
	}
	result, err := a.wait(ctx, op, wantResult)
	runtime.KeepAlive(p)
	return result, err
}

func (a *native) Open(ctx context.Context, name string) (system, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, errors.New("invalid HCS name")
	}
	var h uintptr
	r, _, _ := a.proc("HcsOpenComputeSystem").Call(uintptr(unsafe.Pointer(p)), 0x10000000, uintptr(unsafe.Pointer(&h))) // #nosec G103 -- HCS open ABI with an owned output handle.
	if uint32(r&0xffffffff) == uint32(windows.HCS_E_SYSTEM_NOT_FOUND) {
		return nil, errMissing
	}
	if err = hresult("HcsOpenComputeSystem", r); err != nil {
		return nil, err
	}
	return &nativeSystem{api: a, handle: h}, nil
}

func (a *native) Create(ctx context.Context, c Config) (system, bool, error) {
	if _, err := operationTimeout(ctx); err != nil {
		return nil, true, err
	}
	for _, path := range []string{filepath.Join(c.Root, recordName(c)), filepath.Join(c.Root, markerName(c))} {
		if err := appsandbox.CheckProtectedFile(path); err != nil {
			return nil, true, errors.New("spike ownership and payloads must remain administrator-protected")
		}
	}
	if a.preparedOwner != c.owner() || len(a.payloads) == 0 {
		return nil, true, errors.New("spike payload preparation proof missing")
	}
	for _, proof := range a.payloads {
		if err := proof.verify(); err != nil {
			return nil, true, err
		}
	}
	plan, err := Plan(c)
	if err != nil {
		return nil, true, err
	}
	b, err := json.Marshal(plan)
	if err != nil {
		return nil, true, err
	}
	name, err := windows.UTF16PtrFromString(c.name())
	if err != nil {
		return nil, true, err
	}
	doc, err := windows.UTF16PtrFromString(string(b))
	if err != nil {
		return nil, true, err
	}
	op, _, _ := a.proc("HcsCreateOperation").Call(0, 0)
	if op == 0 {
		return nil, true, errors.New("cannot allocate HCS create operation")
	}
	defer func() { _, _, _ = a.proc("HcsCloseOperation").Call(op) }()
	var h uintptr
	r, _, _ := a.proc("HcsCreateComputeSystem").Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(doc)), op, 0, uintptr(unsafe.Pointer(&h))) // #nosec G103 -- Documented HCS create ABI. No native error document is logged.
	s := &nativeSystem{api: a, handle: h}
	if err = hresult("HcsCreateComputeSystem", r); err != nil {
		return s, !unknownOperation(err), err
	}
	_, err = a.wait(ctx, op, false)
	runtime.KeepAlive(name)
	runtime.KeepAlive(doc)
	return s, !unknownOperation(err), err
}

func unknownOperation(err error) bool {
	var nativeErr *nativeError
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		(errors.As(err, &nativeErr) && (nativeErr.code == uint32(windows.HCS_E_OPERATION_TIMEOUT) || nativeErr.code == uint32(windows.HCS_E_OPERATION_PENDING)))
}

func (s *nativeSystem) Properties(ctx context.Context) (properties, error) {
	var p properties
	b, err := s.api.operation(ctx, "HcsGetComputeSystemProperties", s.handle, `{"PropertyTypes":["Basic"]}`, true)
	if err != nil {
		return p, err
	}
	if json.Unmarshal(b, &p) != nil {
		return p, errors.New("invalid native VM properties")
	}
	return p, nil
}
func (s *nativeSystem) Start(ctx context.Context) error {
	_, err := s.api.operation(ctx, "HcsStartComputeSystem", s.handle, "{}", false)
	return err
}
func (s *nativeSystem) GPU(ctx context.Context) error {
	_, err := s.api.operation(ctx, "HcsModifyComputeSystem", s.handle, gpuDocument(), false)
	return err
}
func (s *nativeSystem) Terminate(ctx context.Context) error {
	_, err := s.api.operation(ctx, "HcsTerminateComputeSystem", s.handle, "{}", false)
	return err
}
func (s *nativeSystem) Close() {
	if s.handle != 0 {
		_, _, _ = s.api.proc("HcsCloseComputeSystem").Call(s.handle)
		s.handle = 0
	}
}

func pinBaseline(c Config) (*os.File, error) {
	if err := appsandbox.CheckProtectedFile(c.Baseline); err != nil {
		return nil, errors.New("spike baseline must be administrator-protected")
	}
	p, err := windows.UTF16PtrFromString(c.Baseline)
	if err != nil {
		return nil, err
	}
	// Hold a read-only handle denying write/delete for the entire trial. The
	// operator must pregrant VM read access to this independent test baseline.
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New("cannot pin read-only spike baseline")
	}
	f := os.NewFile(uintptr(h), c.Baseline)
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil {
		_ = f.Close()
		return nil, errors.New("cannot hash spike baseline")
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), c.BaselineSHA256) {
		_ = f.Close()
		return nil, errors.New("spike baseline SHA-256 differs")
	}
	return f, nil
}

func (a *native) Prepare(ctx context.Context, c Config) error {
	a.preparedOwner = ""
	a.payloads = nil
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := appsandbox.CheckProtectedFile(c.directory()); err != nil {
		return errors.New("spike child must inherit administrator protection")
	}
	// CreateDiffVhd creates only the new child; no host attach, mount, BCD or
	// baseline ACL mutation occurs. Keep the default durable disk semantics.
	if err := vhd.CreateDiffVhd(c.disk(), c.Baseline, 0); err != nil {
		return errors.New("cannot create spike differencing VHDX")
	}
	paths := []string{c.disk()}
	for _, item := range []struct{ method, file string }{{"HcsCreateEmptyGuestStateFile", "vm.vmgs"}, {"HcsCreateEmptyRuntimeStateFile", "vm.vmrs"}} {
		path := filepath.Join(c.directory(), item.file)
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		r, _, _ := a.proc(item.method).Call(uintptr(unsafe.Pointer(p))) // #nosec G103 -- HCS state-file ABI, fixed new files inside the owned directory.
		if err = hresult(item.method, r); err != nil {
			return err
		}
		paths = append(paths, path)
	}
	if len(c.Drivers) != 0 {
		if err := copyDrivers(ctx, c); err != nil {
			return err
		}
		// Grant on each copied file as well as its directory; do not depend
		// on HcsGrantVmAccess recursively changing existing descendants.
		err := filepath.WalkDir(filepath.Join(c.directory(), "drivers"), func(path string, _ fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			paths = append(paths, path)
			return nil
		})
		if err != nil {
			return err
		}
	}
	name, err := windows.UTF16PtrFromString(c.name())
	if err != nil {
		return err
	}
	proofs := make([]payloadProof, 0, len(paths))
	for _, path := range paths {
		if err := appsandbox.CheckProtectedFile(path); err != nil {
			return errors.New("new spike payload is not administrator-protected before VM access grant")
		}
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		p, convErr := windows.UTF16PtrFromString(path)
		if convErr != nil {
			return convErr
		}
		r, _, _ := a.proc("HcsGrantVmAccess").Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(p))) // #nosec G103 -- Grant applies only to new owned files/copies, never the baseline or driver sources.
		if err = hresult("HcsGrantVmAccess", r); err != nil {
			return err
		}
		proof, proofErr := capturePayload(path)
		if proofErr != nil {
			return proofErr
		}
		proofs = append(proofs, proof)
	}
	a.preparedOwner = c.owner()
	a.payloads = proofs
	return nil
}

func copyDrivers(ctx context.Context, c Config) error {
	var total int64
	files := 0
	for i, driver := range c.Drivers {
		if err := appsandbox.CheckProtectedFile(driver.Source); err != nil {
			return errors.New("GPU driver source must be administrator-protected")
		}
		src, err := os.OpenRoot(driver.Source)
		if err != nil {
			return err
		}
		dest := filepath.Join(c.directory(), "drivers", fmt.Sprint(i))
		err = fs.WalkDir(src.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return errors.New("cannot read GPU driver tree")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("GPU driver tree contains a link")
			}
			if entry.IsDir() {
				return os.MkdirAll(filepath.Join(dest, filepath.FromSlash(path)), 0o700)
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return errors.New("GPU driver tree contains a non-regular file")
			}
			files++
			if files > 8192 || info.Size() < 0 || info.Size() > (2<<30)-total {
				return errors.New("GPU driver payload exceeds 8192 files or 2 GiB")
			}
			total += info.Size()
			return copyDriverFile(src, path, filepath.Join(dest, filepath.FromSlash(path)), info.Size())
		})
		err = errors.Join(err, src.Close())
		if err != nil {
			return err
		}
	}
	return nil
}

func copyDriverFile(src *os.Root, relative, destination string, size int64) error {
	in, err := src.Open(relative)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(in, size+1))
	if err == nil && n != size {
		err = errors.New("GPU driver file changed during copy")
	}
	if err == nil {
		err = out.Sync()
	}
	return errors.Join(err, out.Close())
}
