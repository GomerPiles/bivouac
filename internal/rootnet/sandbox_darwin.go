package rootnet

import (
	"errors"
	"os"
	"unsafe"

	"github.com/ebitengine/purego"
)

// ApplySandbox uses deprecated platform Seatbelt APIs; missing/unsupported
// interfaces fail closed. Never broaden this profile for compatibility.
// It is called only in the dedicated child, before any guest frame
// is read. No files, subprocesses, Mach services (including Keychain), inbound
// listeners or host VM handles are admitted. Existing attachment/status FDs and the fixed cache-only broker
// and the separate DNS channel are the child's only capabilities back to its owner; receiving connected
// cache stream FDs does not grant filesystem access or Unix socket dialing.
func ApplySandbox() error {
	lib, err := purego.Dlopen("/usr/lib/libsandbox.1.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return errors.New("network sandbox unavailable")
	}
	initSymbol, err := purego.Dlsym(lib, "sandbox_init")
	if err != nil {
		return errors.New("network sandbox unavailable")
	}
	freeSymbol, err := purego.Dlsym(lib, "sandbox_free_error")
	if err != nil {
		return errors.New("network sandbox unavailable")
	}
	var initialize func(string, uint64, *unsafe.Pointer) int32
	var free func(unsafe.Pointer)
	purego.RegisterFunc(&initialize, initSymbol)
	purego.RegisterFunc(&free, freeSymbol)
	// Add AF_INET6 only with IPv6 admission/link control. ICMP support must
	// use a separately reviewed socket capability, preserving the no-file,
	// no-exec, no-Keychain boundary rather than widening the default rule.
	const profile = `(version 1)
(deny default)
(allow network-outbound (remote tcp "*:*") (remote udp "*:*"))
(deny network-outbound (remote ip "localhost:*"))
(allow sysctl-read (sysctl-name-prefix "net.routetable."))
(allow system-socket (socket-domain AF_INET))
`
	var detail unsafe.Pointer
	result := initialize(profile, 0, &detail)
	if detail != nil {
		free(detail)
	}
	if result != 0 {
		return errors.New("network sandbox activation failed")
	}
	return SandboxedProcess(os.Getpid())
}

// SandboxedProcess verifies blanket Mach-service denial without
// contacting Keychain or executing anything. No-filter checks have no C varargs.
func SandboxedProcess(pid int) error {
	lib, err := purego.Dlopen("/usr/lib/libsandbox.1.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return errors.New("network sandbox verification unavailable")
	}
	symbol, err := purego.Dlsym(lib, "sandbox_check")
	if err != nil {
		return errors.New("network sandbox verification unavailable")
	}
	var check func(int32, string, int32) int32
	purego.RegisterFunc(&check, symbol)
	if pid < 1 || uint64(pid) > 0x7fffffff {
		return errors.New("invalid network sandbox process")
	}
	// SANDBOX_CHECK_NO_REPORT keeps repeated live proofs out of OS denial logs.
	const noReport int32 = 1 << 30
	if check(int32(pid), "mach-lookup", noReport) != 1 { //nolint:gosec // PID is bounded to positive int32 above.
		return errors.New("network sandbox denial unverified")
	}
	return nil
}
