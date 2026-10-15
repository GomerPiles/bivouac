//go:build windows

package cache

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The provider invokes this only inside the disposable, identity-checked VM.
// The guest's administrator installs machine trust without the interactive
// consent needed by a protected CurrentUser ROOT store in an SSH session.
// No host trust store is opened by the manager or provider.
func guestTrust(ctx context.Context, caFile string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) == 0 || len(block.Bytes) > 32<<10 {
		return nil, errors.New("invalid guest proxy CA")
	}
	name, err := windows.UTF16PtrFromString("ROOT")
	if err != nil {
		return nil, err
	}
	// #nosec G103 -- Documented CertOpenStore UTF-16 store-name pointer.
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0, windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, uintptr(unsafe.Pointer(name)))
	runtime.KeepAlive(name)
	if err != nil {
		return nil, errors.New("open disposable guest trust store")
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()
	// #nosec G115 -- Certificate DER length is checked above to be 1..32768.
	cert, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &block.Bytes[0], uint32(len(block.Bytes)))
	if err != nil {
		return nil, errors.New("parse guest CA")
	}
	defer func() { _ = windows.CertFreeCertificateContext(cert) }()
	if err = windows.CertAddCertificateContextToStore(store, cert, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil); err != nil {
		return nil, fmt.Errorf("install disposable guest proxy trust: %w", err)
	}
	var roots []byte
	var previous *windows.CertContext
	for {
		current, err := windows.CertEnumCertificatesInStore(store, previous)
		previous = current
		if err != nil {
			if errors.Is(err, windows.Errno(0x80092004)) {
				break
			}
			return nil, errors.New("enumerate guest trust roots")
		}
		if current.Length > 1<<20 {
			_ = windows.CertFreeCertificateContext(current)
			return nil, errors.New("guest certificate exceeds bound")
		}
		// #nosec G103 -- Certificate bytes remain valid until the next enumeration.
		roots = append(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: unsafe.Slice(current.EncodedCert, int(current.Length))})...)
		if len(roots) > 8<<20 {
			_ = windows.CertFreeCertificateContext(current)
			return nil, errors.New("guest trust bundle exceeds bound")
		}
	}
	return roots, nil
}
