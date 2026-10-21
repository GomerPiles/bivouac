//go:build !windows

package winrunner

import (
	"context"
	"errors"
	"io"
)

func RunGuest(context.Context, string, io.Writer) error {
	return errors.New("windows guest adapter requires Windows")
}
