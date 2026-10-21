//go:build !windows

package appsandbox

import (
	"context"
	"errors"
)

func OpenNativeEngine(context.Context, BrokerOptions) (*Engine, func(), error) {
	return nil, nil, errors.New("appsandbox native broker requires Windows")
}

func DefaultSSHKey() (string, error) {
	return "", errors.New("windows guest transport requires Windows")
}
