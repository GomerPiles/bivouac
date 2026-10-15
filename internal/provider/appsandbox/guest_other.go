//go:build !windows

package appsandbox

import (
	"context"
	"errors"
	"io"
)

func RunWindowsGuest(context.Context, string, io.Writer) error {
	return errors.New("windows guest adapter requires Windows")
}
