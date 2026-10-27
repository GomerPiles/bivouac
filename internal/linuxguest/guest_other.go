//go:build !linux

package linuxguest

import (
	"context"
	"errors"
	"io"
)

func RunLinuxGuest(context.Context, string, io.Reader, io.Writer) error {
	return errors.New("linux guest adapter requires Linux")
}
