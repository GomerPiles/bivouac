//go:build !windows

package hcsspike

import (
	"context"
	"errors"
	"io"
)

func RunCLI(context.Context, []string, io.Writer) error {
	return errors.New("hcs-spike requires Windows amd64")
}
