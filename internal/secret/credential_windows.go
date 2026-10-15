//go:build windows

package secret

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The documented CRED_MAX_CREDENTIAL_BLOB_SIZE is 5*512 bytes. Reject
// larger items instead of silently truncating or splitting private keys.
const maxCredentialBytes = 5 * 512

const (
	credentialGeneric   = 1
	persistLocalMachine = 2
)

// CredentialManager stores generic credentials for the current Windows user,
// persistent across that user's logon sessions on this machine. Values pass
// directly to Advapi32, never through a subprocess or a temporary file.
type CredentialManager struct {
	api credentialAPI // nil selects the native API
}

type credentialAPI interface {
	read(string) ([]byte, error)
	write(string, []byte) error
	delete(string) error
}

func (c CredentialManager) backend() credentialAPI {
	if c.api != nil {
		return c.api
	}
	return nativeCredentials{}
}

func credentialTarget(ctx context.Context, name string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(name) == 0 || len(name) > 128 {
		return "", errors.New("invalid credential item name")
	}
	for i, b := range []byte(name) {
		alphaNum := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
		if !alphaNum && (i == 0 || b != '.' && b != '_' && b != '-') {
			return "", errors.New("invalid credential item name")
		}
	}
	return Service + "/" + name, nil
}

// Get implements Store. The short native call is synchronous; context
// cancellation is checked before dispatch.
func (c CredentialManager) Get(ctx context.Context, name string) ([]byte, error) {
	target, err := credentialTarget(ctx, name)
	if err != nil {
		return nil, err
	}
	return c.backend().read(target)
}

// Set implements Store.
func (c CredentialManager) Set(ctx context.Context, name string, value []byte) error {
	target, err := credentialTarget(ctx, name)
	if err != nil {
		return err
	}
	if len(value) == 0 || len(value) > maxCredentialBytes {
		return fmt.Errorf("credential value must contain 1 through %d bytes", maxCredentialBytes)
	}
	return c.backend().write(target, value)
}

// Delete implements Store; missing items return ErrNotFound.
func (c CredentialManager) Delete(ctx context.Context, name string) error {
	target, err := credentialTarget(ctx, name)
	if err != nil {
		return err
	}
	return c.backend().delete(target)
}

// Default returns the platform store.
func Default() Store { return CredentialManager{} }

// credentialW matches CREDENTIALW in wincred.h, including native pointer
// alignment on both 32-bit and 64-bit Windows.
type credentialW struct {
	Flags, Type             uint32
	TargetName, Comment     *uint16
	LastWritten             windows.Filetime
	BlobSize                uint32
	Blob                    *byte
	Persist, AttributeCount uint32
	Attributes              unsafe.Pointer
	TargetAlias, UserName   *uint16
}

type nativeCredentials struct{}

func credentialError(operation string, err error) error {
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return ErrNotFound
	}
	return fmt.Errorf("credential manager %s: %w", operation, err)
}

func (nativeCredentials) read(target string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return nil, err
	}
	dll := windows.NewLazySystemDLL("advapi32.dll")
	var cred *credentialW
	ok, _, callErr := dll.NewProc("CredReadW").Call(uintptr(unsafe.Pointer(name)), credentialGeneric, 0, uintptr(unsafe.Pointer(&cred))) // #nosec G103 -- UTF16 input and CREDENTIALW output pointers live through the synchronous native call.
	runtime.KeepAlive(name)
	if ok == 0 {
		return nil, credentialError("read", callErr)
	}
	if cred == nil {
		return nil, errors.New("credential manager returned no credential")
	}
	defer func() { _, _, _ = dll.NewProc("CredFree").Call(uintptr(unsafe.Pointer(cred))) }() // #nosec G103 -- CredReadW owns this allocation; CredFree has no return value.
	if cred.BlobSize > maxCredentialBytes || cred.BlobSize != 0 && cred.Blob == nil {
		return nil, errors.New("credential manager returned an invalid blob")
	}
	return append([]byte(nil), unsafe.Slice(cred.Blob, int(cred.BlobSize))...), nil // #nosec G103 -- Size/pointer validated above; copy made before CredFree.
}

func (nativeCredentials) write(target string, value []byte) error {
	if len(value) == 0 || len(value) > maxCredentialBytes {
		return errors.New("invalid credential blob size")
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	cred := credentialW{
		Type: credentialGeneric, TargetName: name, Persist: persistLocalMachine,
		BlobSize: uint32(len(value)), Blob: &value[0], // #nosec G115 -- Bounded to 1..2560 above.
	}
	ok, _, callErr := windows.NewLazySystemDLL("advapi32.dll").NewProc("CredWriteW").Call(uintptr(unsafe.Pointer(&cred)), 0) // #nosec G103 -- CREDENTIALW and referenced Go buffers live through the synchronous native call.
	runtime.KeepAlive(name)
	runtime.KeepAlive(value)
	runtime.KeepAlive(cred)
	if ok == 0 {
		return credentialError("write", callErr)
	}
	return nil
}

func (nativeCredentials) delete(target string) error {
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	ok, _, callErr := windows.NewLazySystemDLL("advapi32.dll").NewProc("CredDeleteW").Call(uintptr(unsafe.Pointer(name)), credentialGeneric, 0) // #nosec G103 -- UTF16 target lives through the synchronous native call.
	runtime.KeepAlive(name)
	if ok == 0 {
		return credentialError("delete", callErr)
	}
	return nil
}
