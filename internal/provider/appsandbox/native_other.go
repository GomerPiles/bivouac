//go:build !windows

package appsandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

func hideCommandWindow(*exec.Cmd) {}

func OpenNativeEngine(context.Context, BrokerOptions) (*Engine, func(), error) {
	return nil, nil, errors.New("appsandbox native broker requires Windows")
}

// CheckProtectedFile has no non-Windows ACL model; the broker is Windows-only.
func CheckProtectedFile(string) error {
	return errors.New("appsandbox native broker requires Windows")
}
func PrivateGuestDirectory(base string) (string, error) {
	return os.MkdirTemp(base, "bivouac-transfer-")
}

func WindowsTransportPaths() (string, string, string, error) {
	return "", "", "", errors.New("windows guest transport requires Windows")
}
