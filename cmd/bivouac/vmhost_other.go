//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
)

func vmhostCmd(context.Context, []string, io.Writer) error {
	return errors.New("the VM host runs only on Windows")
}
